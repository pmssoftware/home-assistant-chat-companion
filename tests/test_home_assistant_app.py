import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]
APP = ROOT / "home_assistant_chat_companion"


class HomeAssistantAppTests(unittest.TestCase):
    def test_repository_and_app_manifests(self) -> None:
        repository = yaml.safe_load((ROOT / "repository.yaml").read_text())
        config = yaml.safe_load((APP / "config.yaml").read_text())
        self.assertEqual(repository["name"], "Home Assistant Chat Apps")
        self.assertEqual(config["slug"], "home_assistant_chat_companion")
        self.assertEqual(config["stage"], "experimental")
        self.assertEqual(set(config["arch"]), {"amd64", "aarch64"})
        self.assertEqual(config["ports"], {"8210/tcp": 8210, "8211/tcp": 8211})
        self.assertEqual(config["backup"], "cold")
        self.assertFalse(config["init"])
        self.assertEqual(config["schema"]["bootstrap_admin_password"], "password")
        self.assertEqual(config["options"]["federation_peers"], [])
        self.assertIn("federation_peers", config["schema"])

    def test_app_is_self_contained_and_uses_explicit_base_image(self) -> None:
        required = {
            "config.yaml", "Dockerfile", "run.sh", "DOCS.md", "README.md",
            "CHANGELOG.md", "icon.png", "logo.png", "translations/en.yaml", "translations/de.yaml",
            "src/hachat_companion/server.py", "src/hachat_companion/cli.py",
        }
        self.assertFalse([item for item in required if not (APP / item).is_file()])
        dockerfile = (APP / "Dockerfile").read_text()
        self.assertIn("FROM ghcr.io/home-assistant/base:latest", dockerfile)
        self.assertIn("openssl", dockerfile)
        self.assertNotIn("ARG BUILD_FROM", dockerfile)
        self.assertIn("COPY src ./src", dockerfile)

    def test_startup_uses_data_storage_and_separate_ports(self) -> None:
        script = (APP / "run.sh").read_text()
        self.assertIn('/data/companion.sqlite3', script)
        self.assertIn('--client-listen 0.0.0.0:8210', script)
        self.assertIn('--federation-listen 0.0.0.0:8211', script)
        self.assertIn('bootstrap-account', script)
        self.assertIn('configure-peer', script)
        self.assertIn('/data/self-signed-fullchain.pem', script)
        self.assertIn('openssl req -x509', script)
        self.assertNotIn('8123', script)


if __name__ == "__main__":
    unittest.main()
