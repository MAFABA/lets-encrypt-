import logging
import os
import sys

import argparse
import configobj
import zope.component

from acme import client as acme_client

from letsencrypt import configuration
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import storage

from letsencrypt.display import util as display_util


logger = logging.getLogger(__name__)


class Manager(object):
    """Certificate Management Class, Revocation and Renewal.

    """
    def __init__(self, installer=None, config=None):
        self.installer = installer
        self.cli_config = configuration.RenewerConfiguration(config)

        self.csha1_vhost = self._get_installed_locations()

        self.certs = self._get_renewable_certs()

    def revoke(self):
        self.display_certs(
            self.certs, "Which certificate would you like to revoke?", "Revoke")

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

    def action_from_menu(self, question, action):
        """List trusted Let's Encrypt certificates."""

        while True:
            if self.certs:
                code, selection = self.display_certs(question, action)

                if code == display_util.OK:
                    acme_client.revoke(self.certs[selection].get_pyopenssl())
                    # revoked_certs = self._safe_revoke([self.certs[selection]])
                    # # Since we are currently only revoking one cert at a time...
                    # if revoked_certs:
                    #     del self.certs[selection]
                elif code == display_util.HELP:
                    more_info_cert(self.certs[selection])
                else:
                    return
            else:
                logger.info(
                    "There are not any trusted Let's Encrypt "
                    "certificates for this server.")
                return

    def display_certs(self, certs, question, ok_label, extra_label=""):
        """Display the certificates in a menu for revocation.

        :param list certs: each is a :class:`letsencrypt.revoker.Cert`

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user's int selection
        :rtype: tuple

        """
        choices = []
        date_format = "%m-%d-%y"
        # 6 is for ' | ' between each
        free_chars = display_util.WIDTH - len(date_format) - len("IR") - 6

        for cert in certs:
            status = "I" if cert.get_fingerprint("sha1") in self.csha1_vhost else ""
            # TODO: Revoked
            status += "R" if False else ""
            choices.append(
                "{names:{name_len}s} | {date:{date_len}s} | {status:2s}".format(
                    names=" ".join(cert.names())[:free_chars],
                    name_len=free_chars,
                    date=cert.notafter().strftime("%m-%d-%y"),
                    date_len=len(date_format),
                    status=status
                )
            )

        code, tag = zope.component.getUtility(interfaces.IDisplay).menu(
            question,
            list_choices, help_label="More Info", ok_label=ok_label,
            extra_label=extra_label, cancel_label="Exit")

        return code, tag

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


def confirm_action(cert, action):
    """Confirm revocation screen.

    :param cert: certificate object
    :type cert: :class:

    :returns: True if user would like to revoke, False otherwise
    :rtype: bool

    """
    return zope.component.getUtility(interfaces.IDisplay).yesno(
        "Are you sure you would like to {action} the following "
        "certificate:{0}{cert}This action cannot be reversed!".format(
            os.linesep, action=action, cert=cert.pretty_print()))


def more_info_cert(cert):
    """Displays more info about the cert.

    :param dict cert: cert dict used throughout revoker.py

    """
    zope.component.getUtility(interfaces.IDisplay).notification(
        "Certificate Information:{0}{1}".format(
            os.linesep, str(cert)),
        height=display_util.HEIGHT)


def success_revocation(cert):
    """Display a success message.

    :param cert: cert that was revoked
    :type cert: :class:`letsencrypt.revoker.Cert`

    """
    zope.component.getUtility(interfaces.IDisplay).notification(
        "You have successfully revoked the certificate for "
        "%s" % cert)