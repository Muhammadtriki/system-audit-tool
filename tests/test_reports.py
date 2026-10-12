import contextlib
import io
import os
import tempfile
import unittest

from system_audit import reports


class ReportTests(unittest.TestCase):
    def quiet(self, function, *args, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return function(*args, **kwargs)

    def test_html_export_escapes_special_characters(self):
        lines = ["<script>alert(1)</script> & more", "PID 1  name<b>"]
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "report.html")
            self.quiet(reports.export_report_html, lines, path)
            with open(path, encoding="utf-8") as f:
                page = f.read()
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt; &amp; more", page)
        self.assertIn("name&lt;b&gt;", page)
        self.assertNotIn("<script>alert", page)

    def test_text_export_has_a_header_and_the_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "report.txt")
            self.quiet(reports.export_report_text, ["first", "second"], path)
            with open(path, encoding="utf-8") as f:
                text = f.read()
        self.assertTrue(text.startswith("System Audit Report - "))
        self.assertTrue(text.endswith("first\nsecond"))

    def test_full_report_content(self):
        lines = reports.build_full_report()
        self.assertTrue(lines[0].startswith("PRIVILEGE LEVEL:"))
        joined = "\n".join(lines)
        for expected in ("CPU:", "RAM:", "Disk free:", "Top 5 processes by CPU:", "Network interfaces:"):
            self.assertIn(expected, joined)

    def test_run_full_report_saves_a_log(self):
        with tempfile.TemporaryDirectory() as folder:
            log_dir = os.path.join(folder, "logs")
            lines = self.quiet(reports.run_full_report, save_log=True, log_dir=log_dir)
            saved = os.listdir(log_dir)
            self.assertEqual(len(saved), 1)
            self.assertTrue(saved[0].startswith("report_") and saved[0].endswith(".txt"))
            self.assertGreater(len(lines), 5)

    def test_run_full_report_can_skip_the_log(self):
        with tempfile.TemporaryDirectory() as folder:
            log_dir = os.path.join(folder, "logs")
            self.quiet(reports.run_full_report, save_log=False, log_dir=log_dir)
            self.assertFalse(os.path.exists(log_dir))


if __name__ == "__main__":
    unittest.main()
