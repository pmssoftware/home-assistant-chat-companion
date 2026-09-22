import unittest

from hachat_companion.cli import parser


class CliTests(unittest.TestCase):
    def test_demo_and_check_commands_are_exposed(self) -> None:
        demo = parser().parse_args(["demo", "--client-port", "9000", "--federation-port", "9001"])
        self.assertEqual((demo.command, demo.client_port, demo.federation_port), ("demo", 9000, 9001))
        check = parser().parse_args(["check"])
        self.assertEqual(check.client_url, "http://127.0.0.1:8210")
        self.assertEqual(check.federation_url, "http://127.0.0.1:8211")
        self.assertEqual(parser().parse_args(["info"]).command, "info")
        bootstrap = parser().parse_args(
            ["bootstrap-account", "--name", "Owner", "--password-stdin"]
        )
        self.assertEqual(bootstrap.command, "bootstrap-account")
        configured = parser().parse_args([
            "configure-peer", "--peer-id", "srv_0123456789abcdef0123456789abcdef",
            "--address", "192.0.2.20", "--port", "8211", "--secret-stdin",
            "--tls-server-name", "chat.example.net",
        ])
        self.assertTrue(configured.secret_stdin)
        self.assertEqual(configured.tls_server_name, "chat.example.net")


if __name__ == "__main__":
    unittest.main()
