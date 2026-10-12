"""Finding and stopping processes by name, with safeguards against stopping the wrong thing."""

import os

import psutil

MIN_NAME_LENGTH = 3

# Processes the operating system depends on. These are never offered for stopping.
PROTECTED_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "systemd", "init", "launchd", "kthreadd",
}


def find_processes_by_name(name):
    """Every running process whose name contains the given text (not case sensitive)."""
    needle = name.lower()
    matches = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if needle in (proc.info["name"] or "").lower():
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return matches


def is_protected(proc):
    """True for core system processes, and for this program and the program that started it."""
    name = (proc.info.get("name") or "").lower()
    return name in PROTECTED_NAMES or proc.pid in (0, 1, os.getpid(), os.getppid())


def split_protected(matches):
    """Split processes into (can be stopped, protected)."""
    stoppable = [proc for proc in matches if not is_protected(proc)]
    protected = [proc for proc in matches if is_protected(proc)]
    return stoppable, protected


def stop_process_by_name(name, ask=None):
    """Stop matching processes after showing them and asking for confirmation.

    Returns how many processes were stopped.
    """
    ask = ask or input
    name = name.strip()
    if len(name) < MIN_NAME_LENGTH:
        print(f"Please type at least {MIN_NAME_LENGTH} characters so only the process you mean is matched.")
        return 0

    matches = find_processes_by_name(name)
    if not matches:
        print(f"No running process matching '{name}' found.")
        return 0

    stoppable, protected = split_protected(matches)
    for proc in protected:
        print(f"  PID {proc.pid}: {proc.info['name']} (protected, will not be stopped)")
    if not stoppable:
        print("Nothing here can be stopped safely.")
        return 0

    print(f"Found {len(stoppable)} process(es) that can be stopped:")
    for proc in stoppable:
        print(f"  PID {proc.pid}: {proc.info['name']}")

    if ask("Stop ALL of these? (yes/no): ").strip().lower() != "yes":
        print("Cancelled.")
        return 0

    stopped = 0
    for proc in stoppable:
        try:
            proc.terminate()
            print(f"[+] Terminated PID {proc.pid}")
            stopped += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
            print(f"[!] Could not stop PID {proc.pid}: {error}")
    return stopped
