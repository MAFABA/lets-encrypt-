import datetime
import logging
import os

import configobj
import pytz
import zope.component

from acme import errors as acme_errors
from acme import client as acme_client
from acme import jose

from letsencrypt import account
from letsencrypt import configuration
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import le_util
from letsencrypt import storage

from letsencrypt.display import util as display_util


logger = logging.getLogger(__name__)


REV_LABEL = "**Revoked**"
EXP_LABEL = "**Expired**"

INSTALL_LABEL = "(Installed)"


class Manager(object):
    """Certificate Management Class, Revocation and Renewal.

    .. todo:: Currently misconfigurations of an installer stop this from loading
        This shouldn't be the case.
    .. todo:: Warnings should be given if the certificate is installed before
        deleting, no matter what the status of OCSP

    :ivar .disco.PluginsRegistry installers: Available (Working + Misconfigured)
        installers
    :ivar dict csha1_vhost: Mapping from cert_sha1 to installed location
    :ivar dict cpath_validity: Mapping from cert_path to validity_label ('str')

    """
    def __init__(self, plugins, config):
        self.installers = _extract_avail_installers(plugins, config)
        self.config = configuration.RenewerConfiguration(config)

        self.csha1_vhost = self._get_installed_locations()

        self.certs = self._get_renewable_certs()

        # Path was chosen instead of sha1 because, we are only checking certs
        # in our immediate database.  There is no fear, as in installed case,
        # where we may not recognize the path, but it is the same cert.
        self.cpath_validity = _get_validity_info(self.certs)

    def revoke(self):
        """Main command to revoke a certificate with a menu."""
        self.action_from_tree(
            "Which certificate(s) would you like to revoke?",
            ("Revoke", self._revoke_action), ("Delete", self._delete_action))

    def _revoke_action(self, selection):
        """Revoke a lineage or certificate."""
        if self._is_lineage(selection):
            cert = self.certs[int(selection)]
            if self.confirm_revocation(cert):
                for version in cert.available_versions("cert"):
                    self._revoke_cert(cert, version)
                success_revocation(cert)
        else:
            cert, version = self._lineage_version(selection)

            if self.confirm_revocation(cert, version):
                self._revoke_cert(cert, version)
                success_revocation(cert, version)

    def _revoke_cert(self, cert, version):
        if self.cpath_validity[cert.version("cert", version)]:
            logger.debug("Certificate is already revoked.")
            return
        acme = self._get_acme_client_for_revoc(cert, version)
        try:
            acme.revoke(jose.ComparableX509(cert.pyopenssl(version)))
        except acme_errors.ClientError:
            logger.error(
                "Unable to revoke certificate at %s",
                cert.version("cert", version))
            raise errors.Error("Failed revocation")
        else:
            self.cpath_validity[cert.version("cert", version)] = REV_LABEL

    def _get_acme_client_for_revoc(self, cert, version):
        # Set up acme_client with proper key
        acc_fs = account.AccountFileStorage(self.config)
        try:
            acc = acc_fs.load(cert.configuration["renewalparams"]["account"])
        except errors.AccountNotFound:
            logger.warning("Unable to find original account for revocation? "
                           "Did you wipe the accounts?")
            logger.debug(
                "Using associated private cert key for acme revocation")

            with open(cert.version("privkey", version)) as key_f:
                cert_key = key_f.read()
            return acme_client.Client(
                self.config.server, key=jose.JWK.load(cert_key))

        else:
            return acme_client.Client(self.config.server, key=acc.key)

    def confirm_revocation(self, cert, version=None):
        """Confirm revocation screen.

        :param storage.RenewableCert cert: Renewable certificate object

        :returns: True if user would like to revoke, False otherwise
        :rtype: bool

        """
        if version is None:
            info = self._more_info_lineage(cert)
            return zope.component.getUtility(interfaces.IDisplay).yesno(
                "Are you sure you would like to revoke all of valid certificates "
                "in this lineage?{br}{info}".format(br=os.linesep, info=info))
        else:
            return zope.component.getUtility(interfaces.IDisplay).yesno(
                "Are you sure you would like to revoke the following "
                "certificate:{br}{info}{br}"
                "This action cannot be reversed!".format(
                    br=os.linesep, info=self._more_info_cert(cert, version)))

    def _delete_action(self, selection):
        ok_delete = True
        if self._is_lineage(selection):

            if self._approved_delete(self.certs[int(selection)]):
                self.certs[int(selection)].delete()
                del(self.certs[int(selection)])
        else:
            zope.component.getUtility(interfaces.IDisplay).notification(
                "Only deleting full lineages is available at this time."
            )

    def _lineage_no_longer_valid(self, cert):
        any(not self.cpath_validity[cert.version("cert", version)]
            for version in cert.available_versions("cert"))

    def _approved_delete(self, cert):
        """Verifies that the user isn't accidently deleting valid certs.

        This verifies known expired and known revoked. An unknown status will
        not prompt the user.

        """
        if any(not self.cpath_validity[cert.version("cert", version)]
               for version in cert.available_versions("cert")):
            return zope.component.getUtility(interfaces.IDisplay).yesno(
                "There are valid certificates in this lineage. If you delete "
                "the certificate you may have difficulty revoking it if "
                "necessary later.{0} Are you sure you want to delete this "
                "lineage?".format(os.linesep))

        return True

    def _get_renewable_certs(self):
        """Get all of the available renewable certs."""
        certs = []
        if not os.path.isdir(self.config.renewal_configs_dir):
            return certs

        for filename in os.listdir(self.config.renewal_configs_dir):
            if not filename.endswith(".conf"):
                continue

            config_path = os.path.join(
                self.config.renewal_configs_dir, filename)
            # Note: This doesn't have to be complete as it is merged with
            # defaults within renewable cert
            rc_config = configobj.ConfigObj(config_path)
            # TODO: this is a dirty hack!
            rc_config.filename = config_path
            try:
                certs.append(storage.RenewableCert(
                    rc_config, cli_config=self.config))
            except errors.CertStorageError as err:
                logger.error("Error loading RenewableCert: %s", str(err))

        return certs

    def action_from_tree(self, question, action, action2):
        """List trusted Let's Encrypt certificates.

        There is a notion that this exact same display can be used for other
        actions... renewal, more complex actions? I apologize for the complexity
        if this code is never used for anything else.

        :param tuple action: ('str', func)
        :param tuple action2: ('str', func)

        """
        while True:
            if self.certs:
                code, selection = self.display_certs(
                    self.certs, question, action[0])

                if code == display_util.OK:
                    action[1](selection)
                elif code == display_util.EXTRA:
                    action2[1](selection)
                elif code == display_util.HELP:
                    # This is less likely to need to be configured.
                    self._more_info(selection)
                else:
                    return
            else:
                logger.info(
                    "There are not any trusted Let's Encrypt "
                    "certificates for this server.")
                return

    def _is_lineage(self, selection):  # pylint: disable=no-self-use
        """Returns true if selection str is a lineage selection."""
        return not "." in selection

    def _lineage_version(self, selection):
        """Returns a tuple containing the lineage and version number."""
        if self._is_lineage(selection):
            raise errors.Error("Lineage was selected, not a certificate.")

        parts = selection.partition(".")
        return (self.certs[int(parts[0])], int(parts[2]))


    def display_certs(self, certs, question, ok_label, extra_label="Delete"):
        """Display the certificates in a menu for revocation.

        :param list certs: each is a :class:`letsencrypt.storage.RenewableCert`
        :param str question: Question to display
        :param str ok_label: Label of ok button
        :param str extra_label: Label of additional button

        :returns: tuple of the form (`code`, `selection`) where
            code is a display exit code
            selection is the user's str selection tag
        :rtype: tuple

        """
        # nodes - where each is a (tag, item, status, depth) tuple
        # `depth` = how many tabs in
        nodes = []
        # 12 is for ' (*) ' and other box spacing requirements
        free_chars = display_util.WIDTH - 12

        for i, cert in enumerate(certs):
            item = (
                "{names:{name_len}s}".format(
                    names=" ".join(cert.names())[:free_chars],
                    name_len=free_chars,
                )
            )
            if i == 0:
                nodes.append((str(i), item, "on", 0))
            else:
                nodes.append((str(i), item, "off", 0))

            self.append_lineage(cert, nodes, str(i))

        code, tag = zope.component.getUtility(interfaces.IDisplay).treeview(
            question,
            nodes, help_label="More Info", ok_label=ok_label,
            extra_label=extra_label, cancel_label="Exit")

        return code, tag

    def installed_status(self, cert, version):
        """Return relevant cert status in string form."""
        if cert.fingerprint("sha1", version) in self.csha1_vhost:
            status = INSTALL_LABEL
        else:
            status = " " * len(INSTALL_LABEL)

        return status

    def append_lineage(self, cert, nodes, l_tag):
        """Appends the certificate lineage to nodes.

        :param .RenewableCert cert: Certificate lineage object
        :param list nodes: List of python dialog nodes
        :param str l_tag: Tag used for lineage node.

        """
        versions = sorted(cert.available_versions("cert"), reverse=True)

        for version in versions:
            nodes.append((
                l_tag + "." + str(version),
                "v.{version} {start} - {end} | {install} {validity}".format(
                    version=version,
                    start=cert.notbefore().strftime("%m-%d-%y"),
                    end=cert.notafter().strftime("%m-%d-%y"),
                    install=self.installed_status(cert, version),
                    validity=self.cpath_validity[cert.version("cert", version)]
                ),
                "off",
                1,
            ))

    def _get_installed_locations(self):
        """Get installed locations of certificates.

        :returns: map from cert sha1 fingerprint to :class:`list` of vhosts
            where the certificate is installed.

        """
        csha1_vhlist = {}

        for installer in self.installers:
            for (cert_path, _, path) in installer.get_all_certs_keys():
                try:
                    with open(cert_path) as cert_file:
                        cert_data = cert_file.read()
                except IOError:
                    continue
                try:
                    cert_obj, _ = crypto_util.pyopenssl_load_certificate(
                        cert_data)
                except errors.Error:
                    continue
                cert_sha1 = cert_obj.digest("sha1")
                if cert_sha1 in csha1_vhlist:
                    csha1_vhlist[cert_sha1].append(path)
                else:
                    csha1_vhlist[cert_sha1] = [path]

        return csha1_vhlist

    def _more_info(self, selection):
        """Displays more info about the cert.

        :param str selection: Selection from display_certs

        """
        if self._is_lineage(selection):
            info = self._more_info_lineage(self.certs[int(selection)])
        else:
            lineage, version = self._lineage_version(selection)
            info = self._more_info_cert(lineage, version)

        zope.component.getUtility(interfaces.IDisplay).notification(
            info, height=display_util.HEIGHT)

    def _more_info_lineage(self, lineage):
        cert_str = []
        for version in sorted(lineage.available_versions("cert"), reverse=True):
            cert_str.append(self._more_info_cert(lineage, version))

        return "Lineage Information:{br}{br}{certs}".format(
            br=os.linesep, certs=os.linesep.join(cert_str))

    def _more_info_cert(self, lineage, version):
        if self.cpath_validity[lineage.version("cert", version)]:
            valid = self.cpath_validity[lineage.version("cert", version)]
        else:
            valid = "Valid"

        status_info = "Installed: {location}{br}Status: {valid}".format(
            location=", ".join(self.csha1_vhost.get(
                lineage.fingerprint("sha1", version), [])),
            br=os.linesep,
            valid=valid)

        return "Certificate v.{version}:{br}" \
               "{cert_info}{br}{status_info}{br}".format(
            version=version, br=os.linesep,
            cert_info=lineage.formatted_str(version),
            status_info=status_info)


def _get_validity_info(certs):
    """Get revocation info for all certs."""
    cpath_validity = {}
    now = datetime.datetime.utcnow()
    now = now.replace(tzinfo=pytz.utc)

    for cert in certs:
        for version in cert.available_versions("cert"):

            if cert.notafter(version) < now:
                cpath_validity[cert.version("cert", version)] = EXP_LABEL
            else:
                cpath_validity[cert.version("cert", version)] = revoked_status(
                    cert.version("cert", version),
                    cert.version("chain", version))

    return cpath_validity


def revoked_status(cert_path, chain_path):
    """Get revoked status for a particular cert version.

    .. todo:: Make this a non-blocking call

    :param str cert_path: Path to certificate
    :param str chain_path: Path to chain certificate

    """
    url, _ = le_util.run_script(
        ["openssl", "x509", "-in", cert_path, "-noout", "-ocsp_uri"])

    url = url.rstrip()
    host = url.partition("://")[2].rstrip("/")
    if not host:
        raise errors.Error(
            "Unable to get OCSP host from cert, url - %s", url)

    # This was a PITA...
    # Thanks to "Bulletproof SSL and TLS - Ivan Ristic" for helping me out
    try:
        output, _ = le_util.run_script(
            ["openssl", "ocsp",
            "-no_nonce", "-header", "Host", host,
            "-issuer", chain_path,
            "-cert", cert_path,
            "-url", url,
            "-CAfile", chain_path])
    except errors.SubprocessError:
        return "(OCSP Failure)"

    return _translate_ocsp_query(cert_path, output)


def _translate_ocsp_query(cert_path, ocsp_output):
    """Returns a label string out of the query."""
    if not "Response verify OK":
        return "Revocation Unknown"
    if cert_path + ": good" in ocsp_output:
        return ""
    elif cert_path + ": revoked" in ocsp_output:
        return REV_LABEL
    else:
        raise errors.Error(
            "Unable to properly parse OCSP output: %s", ocsp_output)


def success_revocation(cert, version=None):
    """Display a success message.

    :param cert: cert that was revoked
    :type cert: :class:`letsencrypt.storage.RenewableCert`

    :param int version: Version if only revoking a single cert in the lineage.

    """
    if version is None:
        msg = "You have successfully revoked all the certificates in this " \
              "lineage. (%d)" % len(cert.available_versions("cert"))
    else:
        msg = "You have successfully revoked the certificate for "
        "%s" % " ".join(
            crypto_util.get_sans_from_pyopenssl(cert.pyopenssl(version)))

    zope.component.getUtility(interfaces.IDisplay).notification(msg)


def _extract_avail_installers(plugins, config):
    """Prepared, Working + Misconfigured IInstallers entry_points."""
     # Get all available installers
    all_installers = plugins.ifaces((interfaces.IInstaller,))

    all_installers.init(config)
    # Verifying Installers actually implement the interface
    verified_installers = all_installers.verify((interfaces.IInstaller,))
    verified_installers.prepare()

    # This is still a plugins registry object
    avail_installers = verified_installers.available()
    avail_installer_ep = avail_installers.values()

    return [ep.init() for ep in avail_installer_ep]