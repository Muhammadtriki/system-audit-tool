import os
import platform
import tempfile
import unittest
from unittest.mock import patch

from system_audit import exposure

ON_WINDOWS = platform.system().lower() == "windows"


class ExposureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.tmp.name, "home")
        self.workdir = os.path.join(self.tmp.name, "work")
        os.mkdir(self.home)
        os.mkdir(self.workdir)

        self.environment = patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home})
        self.environment.start()
        self.addCleanup(self.environment.stop)

        self.original_cwd = os.getcwd()
        os.chdir(self.workdir)
        self.addCleanup(os.chdir, self.original_cwd)

    def make_file(self, path, text="secret"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_nothing_found_in_a_clean_setup(self):
        self.assertEqual(
            exposure.check_sensitive_exposure(self.workdir),
            ["No known sensitive files found in checked locations."],
        )

    def test_env_file_in_a_folder_with_spaces_is_reported_once(self):
        folder = os.path.join(self.tmp.name, "My Projects", "site")
        self.make_file(os.path.join(folder, ".env"))
        findings = exposure.check_sensitive_exposure(os.path.join(self.tmp.name, "My Projects"))
        self.assertEqual(len(findings), 1)
        self.assertIn(os.path.join(folder, ".env"), findings[0])
        self.assertIn(".gitignore", findings[0])

    def test_env_file_in_the_working_folder_is_not_reported_twice(self):
        self.make_file(os.path.join(self.workdir, ".env"))
        findings = exposure.check_sensitive_exposure(self.workdir)
        self.assertEqual(len(findings), 1)

    def test_skipped_folders_are_not_searched(self):
        self.make_file(os.path.join(self.workdir, "node_modules", "pkg", ".env"))
        self.assertEqual(
            exposure.check_sensitive_exposure(self.workdir),
            ["No known sensitive files found in checked locations."],
        )

    @unittest.skipIf(ON_WINDOWS, "permission modes work differently on Windows")
    def test_key_permissions_are_judged(self):
        key = os.path.join(self.home, ".ssh", "id_rsa")
        self.make_file(key)

        os.chmod(key, 0o644)
        self.assertTrue(exposure.check_sensitive_exposure(self.workdir)[0].startswith("[RISKY PERMISSIONS]"))

        os.chmod(key, 0o600)
        self.assertTrue(exposure.check_sensitive_exposure(self.workdir)[0].startswith("[OK]"))

    def test_file_contents_are_never_part_of_a_finding(self):
        key = os.path.join(self.home, ".ssh", "id_rsa")
        self.make_file(key, text="TOP-SECRET-KEY-MATERIAL")
        self.make_file(os.path.join(self.workdir, ".env"), text="PASSWORD=TOP-SECRET-KEY-MATERIAL")
        findings = " ".join(exposure.check_sensitive_exposure(self.workdir))
        self.assertNotIn("TOP-SECRET-KEY-MATERIAL", findings)


if __name__ == "__main__":
    unittest.main()
