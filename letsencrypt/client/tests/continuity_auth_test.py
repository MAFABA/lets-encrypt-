"""Test the ContinuityAuthenticator dispatcher."""
import unittest

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors


class PerformTest(unittest.TestCase):
    """Test client perform function."""

    def setUp(self):
        from letsencrypt.client.continuity_auth import ContinuityAuthenticator

        self.auth = ContinuityAuthenticator(
            mock.MagicMock(server="demo_server.org"))
        self.auth.rec_token.perform = mock.MagicMock(
            name="rec_token_perform", side_effect=gen_client_resp)

    @mock.patch("letsencrypt")
    def test_rec_token1(self):
        token = achallenges.RecoveryToken(challb=None, domain="0")
        responses = self.auth.perform([token])
        self.assertEqual(responses, ["RecoveryToken0"])

    def test_rec_token5(self):
        tokens = []
        for i in xrange(5):
            tokens.append(achallenges.RecoveryToken(challb=None, domain=str(i)))

        responses = self.auth.perform(tokens)

        self.assertEqual(len(responses), 5)
        for i in xrange(5):
            self.assertEqual(responses[i], "RecoveryToken%d" % i)

    def test_unexpected(self):
        self.assertRaises(
            errors.LetsEncryptContAuthError, self.auth.perform, [
                achallenges.DVSNI(challb=None, domain="0", key="invalid_key")])

    def test_chall_pref(self):
        self.assertEqual(
            self.auth.get_chall_pref("example.com"),
            [challenges.RecoveryContact, challenges.RecoveryToken])


def gen_client_resp(chall):
    """Generate a dummy response."""
    return "%s%s" % (chall.__class__.__name__, chall.domain)


if __name__ == '__main__':
    unittest.main()
