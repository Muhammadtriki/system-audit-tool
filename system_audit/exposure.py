"""Permission and exposure checker.

This only checks WHERE sensitive files are and HOW they are protected. It never
opens or reads what is inside them. That is the difference between a security
audit, which points out a risk for you to fix, and a credential harvester,
which collects secrets.
"""

import os
import platform

SENSITIVE_LOCATIONS = [
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519",  # SSH private keys
    "~/.aws/credentials",                   # AWS credentials file
    ".env",                                 # common secrets file in project folders
]
SKIP_FOLDERS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
SAFE_MODES = ("600", "400")  # readable by the owner only


def check_sensitive_exposure(scan_root="."):
    """Return a list of findings as text lines."""
    findings = []
    already_reported = set()  # absolute paths, so paths containing spaces are handled correctly
    on_windows = platform.system().lower() == "windows"

    for location in SENSITIVE_LOCATIONS:
        path = os.path.expanduser(location)
        if not os.path.isfile(path):
            continue
        already_reported.add(os.path.abspath(path))
        if on_windows:
            findings.append(f"[FOUND] {path} (review Windows file/folder permissions manually)")
        else:
            mode = oct(os.stat(path).st_mode)[-3:]
            flag = "[OK]" if mode in SAFE_MODES else "[RISKY PERMISSIONS]"
            findings.append(f"{flag} {path} (mode {mode})")

    # Also look through the given folder for stray .env files, a common real mistake
    for root, folders, files in os.walk(scan_root):
        folders[:] = [folder for folder in folders if folder not in SKIP_FOLDERS]
        if ".env" in files:
            full_path = os.path.join(root, ".env")
            if os.path.abspath(full_path) not in already_reported:
                findings.append(f"[FOUND] {full_path} (make sure this is in .gitignore)")

    return findings or ["No known sensitive files found in checked locations."]
