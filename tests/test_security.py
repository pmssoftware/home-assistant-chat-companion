import unittest

from hachat_companion.security import (
    hash_password,
    new_peer_secret,
    sign_federation_request,
    verify_federation_signature,
    verify_password,
)


class SecurityTests(unittest.TestCase):
    def test_password_hash_round_trip_and_policy(self) -> None:
        encoded = hash_password("correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", encoded))
        self.assertFalse(verify_password("wrong password", encoded))
        with self.assertRaises(ValueError):
            hash_password("too-short")

    def test_federation_signature_binds_every_request_component(self) -> None:
        secret = new_peer_secret()
        timestamp = "1700000000"
        nonce = "nonce_abcdefghijkl"
        signature = sign_federation_request(
            secret, "POST", "/v1/events", timestamp, nonce, b'{"event":1}'
        )
        verified = verify_federation_signature(
            secret=secret,
            peer_id="peer-one",
            method="POST",
            path="/v1/events",
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
            body=b'{"event":1}',
            now=1700000000,
        )
        self.assertEqual(verified.peer_id, "peer-one")
        with self.assertRaisesRegex(ValueError, "invalid_federation_signature"):
            verify_federation_signature(
                secret=secret,
                peer_id="peer-one",
                method="POST",
                path="/v1/events",
                timestamp=timestamp,
                nonce=nonce,
                signature=signature,
                body=b'{"event":2}',
                now=1700000000,
            )


if __name__ == "__main__":
    unittest.main()

