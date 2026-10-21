"""Distribution allowlist tests, without loading any local credentials."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verify_release', Path(__file__).resolve().parents[1] / 'scripts/verify-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_bundle_file_allowlist_rejects_stale_and_private_resources(self):
        for path in ('MacVPN/README.md', 'MacVPN/MacVPN.app/Contents/MacOS/MacVPN',
                     'MacVPN/MacVPN.app/Contents/Resources/app_bridge.py'):
            self.assertTrue(release.allowed_entry(path))
        for path in ('MacVPN/MacVPN.app/Contents/Resources/profiles.json',
                     'MacVPN/MacVPN.app/Contents/Resources/.env',
                     'MacVPN/MacVPN.app/Contents/Resources/old-helper.py',
                     'MacVPN/../README.md', 'other/README.md'):
            self.assertFalse(release.allowed_entry(path))
        self.assertTrue(release.allowed_entry('MacVPN/MacVPN.app/Contents/', True))
        self.assertFalse(release.allowed_entry('MacVPN/MacVPN.app/Contents/old/', True))
