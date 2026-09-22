import ipaddress
import unittest

from hachat_companion.address import UserAddress, parse_ipv4, parse_user_address
from hachat_companion.config import ListenerConfig


class AddressTests(unittest.TestCase):
    def test_local_and_federated_addresses_are_canonical(self) -> None:
        self.assertEqual(parse_user_address("12345678"), UserAddress(12345678))
        remote = parse_user_address("12345678@192.168.1.1:8443")
        self.assertIsInstance(remote.server, ipaddress.IPv4Address)
        self.assertEqual(str(remote), "12345678@192.168.1.1:8443")

    def test_dns_ipv6_whitespace_and_bad_numbers_are_rejected(self) -> None:
        for value in (
            "02345678",
            "1234567",
            "123456789",
            "12345678@example.org",
            "12345678@192.168.001.001:8443",
            "12345678@[::1]:443",
            " 12345678",
            "12345678@127.0.0.1:0",
            "12345678@127.0.0.1:65536",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_user_address(value)

    def test_listener_addresses_are_ipv4_only(self) -> None:
        self.assertEqual(parse_ipv4("127.0.0.1"), "127.0.0.1")
        for value in ("localhost", "::1", "[::1]"):
            with self.assertRaises(ValueError):
                parse_ipv4(value)

    def test_non_loopback_plain_http_requires_an_explicit_override(self) -> None:
        with self.assertRaisesRegex(ValueError, "tls_required"):
            ListenerConfig("0.0.0.0", 8210).validated()
        listener = ListenerConfig("0.0.0.0", 8210, allow_insecure_http=True).validated()
        self.assertTrue(listener.allow_insecure_http)


if __name__ == "__main__":
    unittest.main()
