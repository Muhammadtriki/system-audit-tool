import contextlib
import io
import os
import tempfile
import unittest

from system_audit import downloads


def fail_if_asked(prompt):
    raise AssertionError("should not ask for confirmation")


class DownloadTests(unittest.TestCase):
    def test_filename_from_url(self):
        cases = {
            "https://example.com/files/tool.zip?token=abc#part": "tool.zip",
            "https://example.com/": "downloaded_file",
            "https://example.com/../../etc/passwd": "passwd",
            "https://example.com/a%2F..%2Fb.txt": "b.txt",
            "https://example.com/.hidden": "hidden",
            "https://example.com/my file (1).pdf": "myfile1.pdf",
        }
        for url, expected in cases.items():
            self.assertEqual(downloads.filename_from_url(url), expected, url)

    def test_unique_path_adds_a_number(self):
        with tempfile.TemporaryDirectory() as folder:
            first = downloads.unique_path(folder, "tool.zip")
            self.assertEqual(first, os.path.join(folder, "tool.zip"))
            open(first, "w").close()
            second = downloads.unique_path(folder, "tool.zip")
            self.assertEqual(second, os.path.join(folder, "tool (1).zip"))

    def test_only_https_is_allowed(self):
        with contextlib.redirect_stdout(io.StringIO()):
            for url in ("http://example.com/x.zip", "ftp://example.com/x.zip", "file:///etc/passwd", "x.zip"):
                self.assertIsNone(downloads.download_file(url, ask=fail_if_asked), url)

    def test_declining_downloads_nothing(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            result = downloads.download_file("https://example.com/x.zip", directory=folder, ask=lambda p: "no")
            self.assertIsNone(result)
            self.assertEqual(os.listdir(folder), [])

    def test_save_stream_writes_the_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = os.path.join(folder, "out.bin")
            written = downloads.save_stream(io.BytesIO(b"abcdef"), destination)
            self.assertEqual(written, 6)
            with open(destination, "rb") as f:
                self.assertEqual(f.read(), b"abcdef")

    def test_save_stream_removes_a_file_that_is_too_big(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = os.path.join(folder, "big.bin")
            with self.assertRaises(ValueError):
                downloads.save_stream(io.BytesIO(b"x" * 100), destination, max_bytes=10)
            self.assertFalse(os.path.exists(destination))


if __name__ == "__main__":
    unittest.main()
