"""Recovery Token Identifier Validation Challenge.

Based on draft-barnes-acme, section 6.4.

"""
import zope.component

from letsencrypt.acme import challenges

from letsencrypt.client import interfaces
from letsencrypt.client.display import util as display_util


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

