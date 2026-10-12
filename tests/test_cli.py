import contextlib
import io
import unittest
from unittest.mock import patch

from system_audit import cli


def run(function, *args, inputs=None):
    """Call a CLI function with scripted input and return everything it printed."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        if inputs is None:
            function(*args)
        else:
            with patch("builtins.input", side_effect=inputs):
                function(*args)
    return output.getvalue()


class CliTests(unittest.TestCase):
    def test_menu_lists_all_sixteen_options(self):
        text = run(cli.print_menu)
        self.assertIn("SYSTEM AUDIT TOOL", text)
        for number, _ in cli.MENU_ITEMS:
            self.assertIn(f"{number}.", text)
        self.assertEqual(len(cli.MENU_ITEMS), 16)

    def test_resolve_flag(self):
        self.assertIn("127.0.0.1", run(cli.parse_args_and_run, ["--resolve", "localhost"]))

    def test_scan_flag_on_this_computer_shows_the_warning(self):
        text = run(cli.parse_args_and_run, ["--scan", "127.0.0.1"])
        self.assertIn("permission", text)

    def test_scan_of_another_address_is_cancelled_without_permission(self):
        text = run(cli.port_sweep, "192.168.1.5", inputs=["no"])
        self.assertIn("Cancelled, nothing was scanned.", text)

    def test_menu_resolve_then_exit(self):
        text = run(cli.main, inputs=["3", "localhost", "16"])
        self.assertIn("localhost -> 127.0.0.1", text)
        self.assertIn("Goodbye.", text)

    def test_menu_rejects_a_bad_choice(self):
        text = run(cli.main, inputs=["99", "abc", "16"])
        self.assertEqual(text.count("Invalid choice, pick a number 1-16."), 2)

    def test_export_needs_a_report_first(self):
        text = run(cli.main, inputs=["15", "16"])
        self.assertIn("Run the full report first", text)

    def test_menu_download_refuses_plain_http(self):
        text = run(cli.main, inputs=["7", "http://example.com/x.zip", "16"])
        self.assertIn("Only https:// links are allowed.", text)

    def test_menu_process_name_too_short(self):
        text = run(cli.main, inputs=["8", "ab", "16"])
        self.assertIn("at least 3 characters", text)

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as context, contextlib.redirect_stdout(io.StringIO()) as output:
            cli.parse_args_and_run(["--version"])
        self.assertEqual(context.exception.code, 0)
        self.assertIn("1.0.0", output.getvalue())


if __name__ == "__main__":
    unittest.main()
