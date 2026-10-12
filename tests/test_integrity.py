import contextlib
import io
import os
import tempfile
import unittest

from system_audit import integrity


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = os.path.join(self.tmp.name, "watched")
        os.mkdir(self.folder)
        self.baseline = os.path.join(self.tmp.name, "baseline.json")

    def quiet(self, function, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return function(*args)

    def test_known_sha256(self):
        path = os.path.join(self.folder, "hello.txt")
        with open(path, "wb") as f:
            f.write(b"hello")
        self.assertEqual(
            integrity.sha256_of_file(path),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_unchanged_folder_matches_the_baseline(self):
        write(os.path.join(self.folder, "a.txt"), "one")
        self.assertEqual(self.quiet(integrity.save_baseline, self.folder, self.baseline), 1)
        result = self.quiet(integrity.check_integrity, self.folder, self.baseline)
        self.assertEqual(result, {"added": [], "removed": [], "changed": []})

    def test_changes_additions_and_removals_are_found(self):
        a = os.path.join(self.folder, "a.txt")
        b = os.path.join(self.folder, "b.txt")
        write(a, "one")
        write(b, "two")
        self.quiet(integrity.save_baseline, self.folder, self.baseline)

        write(a, "changed!")
        os.remove(b)
        c = os.path.join(self.folder, "c.txt")
        write(c, "new")

        result = self.quiet(integrity.check_integrity, self.folder, self.baseline)
        self.assertEqual(result, {"added": [c], "removed": [b], "changed": [a]})

    def test_baseline_inside_the_folder_is_not_reported(self):
        write(os.path.join(self.folder, "a.txt"), "one")
        inside = os.path.join(self.folder, "baseline.json")
        self.quiet(integrity.save_baseline, self.folder, inside)
        result = self.quiet(integrity.check_integrity, self.folder, inside)
        self.assertEqual(result, {"added": [], "removed": [], "changed": []})

    def test_missing_baseline_and_bad_folder(self):
        self.assertIsNone(self.quiet(integrity.check_integrity, self.folder, self.baseline))
        self.assertIsNone(self.quiet(integrity.save_baseline, os.path.join(self.tmp.name, "nope"), self.baseline))
        self.assertIsNone(self.quiet(integrity.check_integrity, os.path.join(self.tmp.name, "nope"), self.baseline))


if __name__ == "__main__":
    unittest.main()
