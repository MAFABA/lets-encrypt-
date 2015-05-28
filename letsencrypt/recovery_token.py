"""Recovery Token Identifier Validation Challenge.

Based on draft-barnes-acme, section 6.4.

"""
import zope.component

from acme import challenges

from letsencrypt import le_util
from letsencrypt import interfaces

def perform(achall):
    """Perform the Recovery Token Challenge.

    :param chall: Recovery Token Challenge
    :type chall: :class:`letsencrypt.client.achallenges.RecoveryToken`

    :returns: response
    :rtype: :class:`letsencrypt.acme.challenges.RecoveryTokenResponse`

    """
    code, token = zope.component.getUtility(
        interfaces.IDisplay).input(
            "Recovery Token for identifier: %s " % achall.domain)
    if code != display_util.CANCEL:
        return challenges.RecoveryTokenResponse(token=token)

    return None

