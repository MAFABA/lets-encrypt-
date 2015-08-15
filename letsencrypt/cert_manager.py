import logging
import os


import argparse
import configobj
import zope.component

from acme import errors as acme_errors
from acme import client as acme_client

from letsencrypt import configuration
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import storage

from letsencrypt.display import util as display_util


logger = logging.getLogger(__name__)


class Manager(object):
    """Certificate Management Class, Revocation and Renewal."""
    def __init__(self, installer=None, config=None):
        self.installer = installer
        self.cli_config = configuration.RenewerConfiguration(config)

        self.csha1_vhost = self._get_installed_locations()

        self.certs = self._get_renewable_certs()

    def revoke(self):
        self.action_from_tree(
            "Which certificate would you like to revoke?",
            "Revoke", self._revoke_action)

    def _revoke_action(self, selection):
        """Revoke a lineage or certificate."""
        if self._selected_lineage(selection):
            self._revoke_lineage(self.certs[int(selection)])
        else:
            cert, version = self._lineage_version(selection)
            if confirm_revocation(cert, version):
                self._revoke_cert(cert, version)
                success_revocation(cert, version)

    def _revoke_cert(self, cert, version):
        try:
            acme_client.revoke(
                cert.version("cert", version),
                cert.version("privkey", version))
        except acme_errors.ClientError:
            logger.error(
                "Unable to revoke certificate at %s",
                cert.version("cert", version))
            raise errors.Error("Failed revocation")

    def _revoke_lineage(self, cert):
        if self._revoke_lineage_confirmation(cert):
            for version in cert.available_versions("cert"):
                self._revoke_cert(cert, version)

    def _revoke_lineage_confirmation(self, cert):
        info = self._more_info_lineage(cert)
        return zope.component.getUtility(interfaces.IDisplay).yesno(
            "Are you sure you would like to revoke all of valid certificates in"
            "this lineage?{br}{info}".format(br=os.linesep, info=info))

    def _delete(self, selection):
        if self._selected_lineage(selection):
            self.certs[int(selection)].delete()
            del(self.certs[int(selection)])
        else:
            zope.component.getUtility(interfaces.IDisplay).notification(
                "Only deleting full lineages is available at this time."
            )

    def _get_renewable_certs(self):
        certs = []
        if not os.path.isdir(self.cli_config.renewal_configs_dir):
            return certs

        for filename in os.listdir(self.cli_config.renewal_configs_dir):
            if not filename.endswith(".conf"):
                continue

            config_path = os.path.join(
                self.cli_config.renewal_configs_dir, filename)
            # Note: This doesn't have to be complete as it is merged with
            # defaults within renewable cert
            rc_config = configobj.ConfigObj(config_path)
            # TODO: this is a dirty hack!
            rc_config.filename = config_path
            try:
                certs.append(storage.RenewableCert(
                    rc_config, cli_config=self.cli_config))
            except errors.CertStorageError as err:
                logger.error("Error loading RenewableCert: %s", str(err))

        return certs

    def action_from_tree(self, question, action, action_func):
        """List trusted Let's Encrypt certificates."""

        while True:
            if self.certs:
                code, selection = self.display_certs(
                    self.certs, question, action)

                if code == display_util.OK:
                    print selection
                    action_func(selection)
                if code == display_util.EXTRA:
                    print selection
                    self._delete(selection)
                elif code == display_util.HELP:
                    print selection
                    self._more_info(selection)
                else:
                    return
            else:
                logger.info(
                    "There are not any trusted Let's Encrypt "
                    "certificates for this server.")
                return

    def _selected_lineage(self, selection):  # pylint: disable=no-self-use
        return not "." in selection

    def _lineage_version(self, selection):
        """Returns a tuple containing the lineage and version number."""
        if self._selected_lineage(selection):
            raise errors.Error("Lineage was selected, not a certificate.")

        parts = selection.partition(".")
        return (self.certs[int(parts[0])], int(parts[2]))


    def display_certs(self, certs, question, ok_label, extra_label="Delete"):
        """Display the certificates in a menu for revocation.

        :param list certs: each is a :class:`letsencrypt.storage.RenewableCert`

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user's int selection
        :rtype: tuple

        """
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

    def get_cert_status(self, cert, version):
        status = ""
        if cert.fingerprint("sha1", version) in self.csha1_vhost:
            status += "Installed"
        # TODO: Revoked

        return status

    def append_lineage(self, cert, nodes, l_tag):
        versions = sorted(cert.available_versions("cert"), reverse=True)

        for version in versions:
            nodes.append((
                l_tag + "." + str(version),
                "Version {version} {start} - {end} | {status}".format(
                    version=version,
                    start=cert.notbefore().strftime("%m-%d-%y"),
                    end=cert.notafter().strftime("%m-%d-%y"),
                    status=self.get_cert_status(cert, version)
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

        if self.installer is None:
            return csha1_vhlist

        for (cert_path, _, path) in self.installer.get_all_certs_keys():
            try:
                with open(cert_path) as cert_file:
                    cert_data = cert_file.read()
            except IOError:
                continue
            try:
                cert_obj, _ = crypto_util.pyopenssl_load_certificate(cert_data)
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
        if self._selected_lineage(selection):
            info = self._more_info_lineage(self.certs[int(selection)])
        else:
            lineage, version = self._lineage_version(selection)
            info = self._more_info_cert(lineage, version)

        zope.component.getUtility(interfaces.IDisplay).notification(
            info, height=display_util.HEIGHT)

    def _more_info_lineage(self, lineage):
        cert_str = []
        for version in sorted(lineage.available_versions("cert"), reverse=True):
            cert_str.append(
                "Certificate {version}:{br}{cert_info}".format(
                    version=version, br=os.linesep,
                    cert_info=lineage.formatted_str(version)))
        return "Lineage Information:{br}{certs}".format(
            br=os.linesep, certs=os.linesep.join(cert_str))

    def _more_info_cert(self, lineage, version):
        return "Certificate Information:{br}{cert_info}".format(
            br=os.linesep, cert_info=lineage.formatted_str(version))

def _paths_parser(parser):
    add = parser.add_argument_group("paths").add_argument
    add("--config-dir", default=cli.flag_default("config_dir"),
        help=cli.config_help("config_dir"))
    add("--work-dir", default=cli.flag_default("work_dir"),
        help=cli.config_help("work_dir"))
    add("--logs-dir", default=cli.flag_default("logs_dir"),
        help="Path to a directory where logs are stored.")

    return parser


def _create_parser():
    parser = argparse.ArgumentParser()
    #parser.add_argument("--cron", action="store_true", help="Run as cronjob.")
    # pylint: disable=protected-access
    return _paths_parser(parser)


def confirm_revocation(cert, version):
    """Confirm revocation screen.

    :param cert: Renewable certificate object
    :type cert: :class:

    :returns: True if user would like to revoke, False otherwise
    :rtype: bool

    """
    return zope.component.getUtility(interfaces.IDisplay).yesno(
        "Are you sure you would like to revoke the following "
        "certificate:{0}{cert}This action cannot be reversed!".format(
            os.linesep, cert=cert.formatted_str(version)))


def success_revocation(cert):
    """Display a success message.

    :param cert: cert that was revoked
    :type cert: :class:`letsencrypt.revoker.Cert`

    """
    zope.component.getUtility(interfaces.IDisplay).notification(
        "You have successfully revoked the certificate for "
        "%s" % cert)