import os
import shutil
import subprocess
import tempfile
import unittest

import psutil

from system_audit import processes


class ProcessTests(unittest.TestCase):
    def test_short_names_are_refused_without_asking(self):
        def fail_if_asked(prompt):
            raise AssertionError("should not ask for confirmation")

        self.assertEqual(processes.stop_process_by_name("ab", ask=fail_if_asked), 0)

    def test_unknown_name_stops_nothing(self):
        self.assertEqual(processes.stop_process_by_name("no-such-process-xyz", ask=lambda p: "yes"), 0)

    def test_this_program_is_protected(self):
        own_name = psutil.Process().name()
        matches = processes.find_processes_by_name(own_name)
        stoppable, protected = processes.split_protected(matches)
        self.assertIn(os.getpid(), [proc.pid for proc in protected])
        self.assertNotIn(os.getpid(), [proc.pid for proc in stoppable])

    def test_core_system_names_are_protected(self):
        class FakeProcess:
            pid = 4242
            info = {"name": "LSASS.EXE"}

        self.assertTrue(processes.is_protected(FakeProcess()))

    def test_declining_stops_nothing(self):
        child, folder = self._start_uniquely_named_process()
        try:
            self.assertEqual(processes.stop_process_by_name("auditsleeptest", ask=lambda p: "no"), 0)
            self.assertIsNone(child.poll())  # still running
        finally:
            child.kill()
            child.wait()
            shutil.rmtree(folder)

    def test_confirmed_stop_terminates_the_process(self):
        child, folder = self._start_uniquely_named_process()
        try:
            self.assertEqual(processes.stop_process_by_name("auditsleeptest", ask=lambda p: "yes"), 1)
            child.wait(timeout=5)
            self.assertIsNotNone(child.poll())
        finally:
            child.kill()
            child.wait()
            shutil.rmtree(folder)

    def _start_uniquely_named_process(self):
        sleep_path = shutil.which("sleep")
        if not sleep_path:
            self.skipTest("the sleep command is not available")
        folder = tempfile.mkdtemp()
        copy = os.path.join(folder, "auditsleeptest")
        shutil.copy(sleep_path, copy)
        return subprocess.Popen([copy, "60"]), folder


if __name__ == "__main__":
    unittest.main()
