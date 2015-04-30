"""Continuity Authenticator"""
import zope.interface

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import recovery_contact
from letsencrypt.client import recovery_token


class ContinuityAuthenticator(object):
    """IAuthenticator for
    :const:`~letsencrypt.acme.challenges.ContinuityChallenge` class challenges.

    :ivar rec_token: Performs "recoveryToken" challenges
    :type rec_token: :class:`letsencrypt.client.recovery_token.RecoveryToken`

    """
    zope.interface.implements(interfaces.IAuthenticator)

    # This will have an installer soon for get_key/cert purposes
    def __init__(self, config):
        """Initialize Client Authenticator.

        :param config: Configuration.
        :type config: :class:`letsencrypt.client.interfaces.IConfig`

        """
        self.rec_token = recovery_token.RecoveryToken(
            config.server, config.rec_token_dir)
        self.rec_contact = recovery_contact.RecoveryContact()

    def get_chall_pref(self, domain):
        """Return list of challenge preferences."""
        return [challenges.RecoveryContact, challenges.RecoveryToken]

    def perform(self, achalls):
        """Perform continuity challenges for IAuthenticator.

        :param achalls: List of Continuity
            :class:`~letsencrypt.client.achallenges.AnnotatedChallenges`
        :type achalls: list

        :returns: List of ACME
            :class:`~letsencrypt.acme.challenges.ChallengeResponse` instances
            or if the :class:`~letsencrypt.acme.challenges.Challenge` cannot
            be fulfilled then:

            ``None``
              Authenticator can perform challenge, but not at this time.
            ``False``
              Authenticator will never be able to perform (error).

        :rtype: :class:`list` of
            :class:`letsencrypt.acme.challenges.ChallengeResponse`

        """
        responses = []
        for achall in achalls:
            if isinstance(achall, achallenges.RecoveryToken):
                responses.append(recovery_token.perform(achall))
            elif isinstance(achall, achallenges.RecoveryContact):
                responses.append(recovery_contact.perform(achall))
            else:
                raise errors.LetsEncryptContAuthError("Unexpected Challenge")
        return responses

    def cleanup(self, achalls):
        """Cleanup call for IAuthenticator.

        The continuity challenges don't have any cleanup requirements.

        """
        pass
