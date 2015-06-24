""" Tests for letsencrypt.client.recovery_contact."""
import unittest

from letsencrypt.acme import challenges
from letsencrypt.client import achallenges
from letsencrypt.client.display import util as display_util
from letsencrypt.client.tests import acme_util

class RecoveryContactTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.recovery_contact import RecoveryContact
        self.rec_contact = RecoveryContact()
        self.achall_full = achallenges.RecoveryContact(
            acme_util.RECOVERY_CONTACT, "example.com")
        self.achall_empty = achallenges.RecoveryContact(
        challenges.RecoveryContact(), "example.com")


    @mock.patch("letsencrypt.client.recovery_contact.zope.component.getUtility")
    def test_perform_clean_manual(self, mock_util):
        mock_util().input.return_value = (display_util.OK, "token")
        resp = self.rec_contact.perform(self.achall_empty)
        self.assertEqual(
            challenges.RecoveryContactResponse(token="token"), resp)
