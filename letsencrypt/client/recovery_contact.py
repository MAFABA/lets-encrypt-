"""Recovery Contact Identifier Validation Challenge."""
import httplib
import logging
import time

import requests
import zope.component

from letsencrypt.acme import challenges
from letsencrypt.client import display
from letsencrypt.client import errors
from letsencrypt.client import interfaces


class RecoveryContact(object):
    """Recovery Contact Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.3.

    .. note:: I chose to keep this a class to be consistent with other challenge
        modules and it will also probably require state in the future.

    .. todo:: This will have to be extended once the renewal configuration
        and registration setup is finished. Which email should the user expect
        it to go etc..

    """
    def perform(self, achall, delay=3, assume_failed_after=60):
        """Perform the Recovery Contact Challenge.

        :param achall: Recovery Contact Challenge
        :type achall: :class:`letsencrypt.client.achallenges.RecoveryContact`

        :returns: Response or None/False if the challenge cannot be completed
        :rtype: :class:`letsencrypt.acme.challenges.RecoveryContactResponse` or
            False

        """
        if achall.activation_url is not None:
            try:
                self._activate_challenge(achall)
            except errors.NetworkError:
                return False

        return self._gen_response(achall, delay, assume_failed_after)

    def cleanup(self, achall):
        """No cleanup necessary currently."""
        pass

    def _activate_challenge(self, achall):
        try:
            activation_response = requests.get(achall.activation_url)
        except requests.exceptions.RequestException:
            # This takes care of all possible problems...
            msg = "Unable to activate Recovery Contact Challenge"
            logging.warning(msg)
            raise errors.NetworkError(msg)

        if activation_response.status_code != httplib.OK:
            logging.debug(
                "Received unexpected status_code from Recovery Contact "
                "activationURL: %d", activation_response.status_code)
            raise errors.NetworkError("Received unexpected status_code")

    def _gen_response(self, achall, delay, assume_failed_after):
        # This should use the database when it is available to give a full
        # address
        if achall.contact is not None:
            contact_stub = "at %s" % achall.contact
        else:
            contact_stub = ""

        chall_description = (
            "You should be receiving an email {contact} to help prove "
            "authorization of {dom}".format(
                contact=contact_stub, dom=achall.domain))

        if achall.success_url is not None:
            return self._handle_polling(
                achall, delay, assume_failed_after, chall_description)
        else:
            code, token = zope.component.getUtility(interfaces.IDisplay).input(
                "%s - Please input the token found within the "
                "email: " % chall_description)
            if code != display.CANCEL:
                return challenges.RecoveryContactResponse(token=token)

        # Returns False if user cancels manual input of response
        return False

    def _handle_polling(
            self, achall, delay, assume_failed_after, chall_description):
        wait = True
        while wait:
            zope.component.getUtility(interfaces.IDisplay).notification(
                "%s - Please click the link in the email to "
                "continue." % chall_description, pause=False)
            for _ in range(assume_failed_after / delay):
                logging.debug("Waiting for %d seconds...", delay)
                time.sleep(delay)
                try:
                    success_response = requests.get(achall.success_url)
                # TODO: Most appropriate error handling?
                except (requests.exceptions.ConnectionError,
                        requests.exceptions.HTTPError):
                    pass
                except requests.exceptions.RequestException:
                    logging.debug("Failure while polling for "
                                  "RecoveryContact successURL")
                    return False
                if success_response.status_code == httplib.OK:
                    return challenges.RecoveryContactResponse()

            wait = zope.component.getUtility(interfaces.IDisplay).yesno(
                "Do you need more time?")
        logging.warning("Recovery Contact timed out. Challenge failed")
        return False