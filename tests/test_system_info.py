import unittest

from system_audit import system_info


class FakeKey:
    def __init__(self, node):
        self.node = node

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeRegistry:
    """A stand-in for the Windows winreg module, so the Windows code can be tested anywhere."""

    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"

    def __init__(self, tree):
        self.tree = tree

    def OpenKey(self, parent, sub_path):
        if isinstance(parent, FakeKey):
            node = parent.node.get("subkeys", {}).get(sub_path)
        else:
            node = self.tree.get((parent, sub_path))
        if node is None:
            raise FileNotFoundError(sub_path)
        return FakeKey(node)

    def QueryInfoKey(self, key):
        return (len(key.node.get("subkeys", {})), len(key.node.get("values", {})), 0)

    def EnumKey(self, key, index):
        return list(key.node["subkeys"])[index]

    def QueryValueEx(self, key, name):
        values = key.node.get("values", {})
        if name not in values:
            raise FileNotFoundError(name)
        return (values[name], 1)

    def EnumValue(self, key, index):
        items = list(key.node.get("values", {}).items())
        if index >= len(items):
            raise OSError("no more values")
        name, value = items[index]
        return (name, value, 1)


class SystemInfoTests(unittest.TestCase):
    def test_cpu_telemetry_has_sensible_values(self):
        cpu = system_info.get_cpu_telemetry()
        self.assertGreaterEqual(cpu["logical_cores"], 1)
        self.assertTrue(0 <= cpu["overall_percent"] <= 100)
        self.assertEqual(len(cpu["per_core_percent"]), cpu["logical_cores"])

    def test_memory_and_disk_telemetry(self):
        data = system_info.get_memory_and_disk_telemetry()
        self.assertGreater(data["ram_total_gb"], 0)
        self.assertGreater(data["disk_total_gb"], 0)
        self.assertTrue(0 <= data["ram_percent"] <= 100)

    def test_top_processes_respects_limit_and_order(self):
        top_cpu, top_mem = system_info.get_top_processes(limit=3)
        self.assertLessEqual(len(top_cpu), 3)
        self.assertLessEqual(len(top_mem), 3)
        memory = [p["memory_percent"] for p in top_mem]
        self.assertEqual(memory, sorted(memory, reverse=True))
        for proc in top_cpu + top_mem:
            self.assertEqual(set(proc), {"pid", "name", "cpu_percent", "memory_percent"})

    def test_environment_info(self):
        info = system_info.get_environment_info()
        self.assertEqual(info["path_count"], len(info["paths"]))

    def test_privileges_returns_a_bool(self):
        self.assertIsInstance(system_info.check_privileges(), bool)

    def test_firewall_status_is_text(self):
        self.assertIsInstance(system_info.get_firewall_status(), str)

    def test_installed_software_is_a_list_of_text(self):
        lines = system_info.get_installed_software(limit=5)
        self.assertLessEqual(len(lines), 5)
        self.assertTrue(all(isinstance(line, str) for line in lines))

    def test_startup_programs_is_a_list(self):
        self.assertIsInstance(system_info.get_startup_programs(), list)

    def test_windows_installed_software_from_the_registry(self):
        uninstall_path = system_info.UNINSTALL_KEYS[0][1]
        registry = FakeRegistry({
            ("HKLM", uninstall_path): {"subkeys": {
                "a": {"values": {"DisplayName": "Zeta App", "DisplayVersion": "1.0"}},
                "b": {"values": {"DisplayName": "alpha tool"}},
                "c": {"values": {"Publisher": "no display name, so not a real program"}},
            }},
        })
        programs = system_info.read_windows_installed_software(registry)
        self.assertEqual(programs, [("alpha tool", ""), ("Zeta App", "1.0")])

    def test_windows_installed_software_with_no_registry_keys(self):
        self.assertEqual(system_info.read_windows_installed_software(FakeRegistry({})), [])

    def test_windows_run_entries_from_the_registry(self):
        hive_name, run_path = system_info.RUN_KEYS[0]
        registry = FakeRegistry({
            ("HKCU", run_path): {"values": {"OneDrive": r"C:\Apps\OneDrive.exe", "Updater": r"C:\Apps\up.exe"}},
        })
        entries = system_info.read_registry_run_entries(registry)
        self.assertEqual(entries, [
            r"[Registry Run] OneDrive -> C:\Apps\OneDrive.exe",
            r"[Registry Run] Updater -> C:\Apps\up.exe",
        ])


if __name__ == "__main__":
    unittest.main()
