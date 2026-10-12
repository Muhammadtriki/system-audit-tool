"""Facts about this computer: privileges, CPU, memory, disk, processes,
installed software, startup programs and the firewall."""

import ctypes
import os
import platform
import shutil
import subprocess

import psutil

try:
    import winreg  # Only exists on Windows
except ImportError:
    winreg = None

COMMAND_TIMEOUT = 30  # seconds before a helper command is given up on


def current_system():
    return platform.system().lower()


def run_command(command):
    """Run a helper command and return what it printed. A failure gives an empty string."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout


# ------------------------------------------------------------------------------
# Privileges and environment
# ------------------------------------------------------------------------------
def check_privileges():
    """True when running as Administrator (Windows) or root (Linux and macOS)."""
    if current_system() == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def get_environment_info():
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    current_user = os.environ.get("USER") or os.environ.get("USERNAME")
    return {"user": current_user, "path_count": len(path_dirs), "paths": path_dirs}


# ------------------------------------------------------------------------------
# CPU, memory and disk
# ------------------------------------------------------------------------------
def get_cpu_telemetry():
    psutil.cpu_times_percent(interval=None)  # the first call only sets a baseline
    per_core_percent = psutil.cpu_percent(interval=1, percpu=True)
    cpu_times = psutil.cpu_times_percent(interval=None)  # covers the second measured above

    try:
        freq = psutil.cpu_freq()
    except (NotImplementedError, OSError):
        freq = None
    freq_current = f"{freq.current:.0f} MHz" if freq else "N/A"
    freq_max = f"{freq.max:.0f} MHz" if freq and freq.max else "N/A"

    overall_cpu_percent = sum(per_core_percent) / len(per_core_percent) if per_core_percent else 0.0
    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "freq_current": freq_current,
        "freq_max": freq_max,
        "overall_percent": overall_cpu_percent,
        "per_core_percent": per_core_percent,
        "user_time": getattr(cpu_times, "user", 0.0),
        "system_time": getattr(cpu_times, "system", 0.0),
        "idle_time": getattr(cpu_times, "idle", 0.0),
    }


def get_memory_and_disk_telemetry():
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))  # the drive the program runs from
    gigabyte = 1024 ** 3
    return {
        "ram_total_gb": mem.total / gigabyte,
        "ram_used_gb": mem.used / gigabyte,
        "ram_percent": mem.percent,
        "disk_total_gb": disk.total / gigabyte,
        "disk_free_gb": disk.free / gigabyte,
        "disk_percent": disk.percent,
    }


def get_top_processes(limit=5):
    """Return (top by CPU, top by memory).

    The same Process objects are used for both CPU readings, because psutil
    needs a first call on an object to set the baseline for the second call.
    """
    procs = list(psutil.process_iter(["pid", "name", "memory_percent"]))
    for proc in procs:
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.cpu_percent(interval=0.1)

    processes = []
    for proc in procs:
        try:
            processes.append({
                "pid": proc.info["pid"],
                "name": proc.info["name"] or "Unknown",
                "cpu_percent": proc.cpu_percent(interval=None),
                "memory_percent": proc.info["memory_percent"] or 0.0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    top_cpu = sorted(processes, key=lambda p: p["cpu_percent"], reverse=True)[:limit]
    top_mem = sorted(processes, key=lambda p: p["memory_percent"], reverse=True)[:limit]
    return top_cpu, top_mem


# ------------------------------------------------------------------------------
# Installed software
# ------------------------------------------------------------------------------
UNINSTALL_KEYS = [
    ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKEY_LOCAL_MACHINE", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def read_windows_installed_software(registry=None):
    """Return (name, version) pairs from the Windows Uninstall registry keys, sorted by name.

    This reads the registry directly. The older Win32_Product method is slow and
    can trigger Windows Installer repair checks, so it is avoided on purpose.
    """
    registry = registry or winreg
    programs = set()
    for hive_name, path in UNINSTALL_KEYS:
        try:
            with registry.OpenKey(getattr(registry, hive_name), path) as key:
                subkey_count = registry.QueryInfoKey(key)[0]
                for index in range(subkey_count):
                    try:
                        subkey_name = registry.EnumKey(key, index)
                        with registry.OpenKey(key, subkey_name) as subkey:
                            name = str(registry.QueryValueEx(subkey, "DisplayName")[0])
                            try:
                                version = str(registry.QueryValueEx(subkey, "DisplayVersion")[0])
                            except OSError:
                                version = ""
                        programs.add((name, version))
                    except OSError:
                        continue  # an entry without a display name is not a real program
        except OSError:
            continue  # this registry location does not exist
    return sorted(programs, key=lambda program: program[0].lower())


def get_installed_software(limit=20):
    system = current_system()
    try:
        if system == "linux":
            if shutil.which("dpkg"):
                return run_command(["dpkg", "-l"]).splitlines()[5:][:limit]
            if shutil.which("rpm"):
                return run_command(["rpm", "-qa"]).splitlines()[:limit]
            return ["[!] Neither dpkg nor rpm found on this system."]
        if system == "windows":
            if winreg is None:
                return ["[!] The Windows registry is not available."]
            programs = read_windows_installed_software()
            return [f"{name}  {version}".rstrip() for name, version in programs[:limit]]
        return [f"[!] Not implemented for {system}."]
    except Exception as error:
        return [f"[!] Error retrieving installed software: {error}"]


# ------------------------------------------------------------------------------
# Startup programs
# ------------------------------------------------------------------------------
RUN_KEYS = [
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def read_registry_run_entries(registry=None):
    """List the programs registered to start automatically in the Windows Run keys."""
    registry = registry or winreg
    entries = []
    for hive_name, path in RUN_KEYS:
        label = path.split("\\")[-1]
        try:
            with registry.OpenKey(getattr(registry, hive_name), path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = registry.EnumValue(key, index)
                    except OSError:
                        break  # no more values in this key
                    entries.append(f"[Registry {label}] {name} -> {value}")
                    index += 1
        except OSError:
            continue  # this registry location does not exist
    return entries


def get_startup_programs():
    """Persistence (what survives a reboot) is one of the first things a security review checks."""
    system = current_system()
    entries = []

    if system == "windows" and winreg is not None:
        entries.extend(read_registry_run_entries())
        startup_folder = os.path.join(
            os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"
        )
        if os.path.isdir(startup_folder):
            entries.extend(f"[Startup folder] {item}" for item in os.listdir(startup_folder))

    elif system == "linux":
        if shutil.which("systemctl"):
            output = run_command(["systemctl", "list-unit-files", "--type=service", "--state=enabled"])
            entries.extend(f"[systemd] {line}" for line in output.splitlines() if ".service" in line)
        if shutil.which("crontab"):
            output = run_command(["crontab", "-l"])
            entries.extend(f"[cron] {line}" for line in output.splitlines() if line.strip())

    else:
        entries.append(f"[!] Startup audit not implemented for {system}.")

    return entries


# ------------------------------------------------------------------------------
# Firewall
# ------------------------------------------------------------------------------
def get_firewall_status():
    system = current_system()
    if system == "windows":
        output = run_command(["netsh", "advfirewall", "show", "allprofiles", "state"])
    elif system == "linux":
        if shutil.which("ufw"):
            output = run_command(["ufw", "status"])
        elif shutil.which("iptables"):
            output = run_command(["iptables", "-L"])
        else:
            return "[!] Neither ufw nor iptables found."
    else:
        return f"[!] Firewall check not implemented for {system}."
    return output or "[!] The firewall command returned nothing (it may need admin/root rights)."
