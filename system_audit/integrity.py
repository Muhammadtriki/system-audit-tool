"""File integrity checker.

Hash every file in a folder once and save the result as a baseline. Check again
later and it flags anything changed, added or removed, the same idea that tools
like Tripwire use to detect tampering.
"""

import hashlib
import json
import os

BASELINE_FILE = "integrity_baseline.json"


def sha256_of_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_folder(folder_path, skip=None):
    """Return {file path: sha256} for every readable file under the folder."""
    skip = os.path.abspath(skip) if skip else None
    hashes = {}
    for root, _, files in os.walk(folder_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            if skip and os.path.abspath(full_path) == skip:
                continue  # never hash the baseline file itself
            try:
                hashes[full_path] = sha256_of_file(full_path)
            except OSError:
                pass  # skip files we cannot read
    return hashes


def save_baseline(folder_path, baseline_file=BASELINE_FILE):
    """Save the current hashes. Returns how many files were recorded, or None for a bad folder."""
    if not os.path.isdir(folder_path):
        print(f"[!] {folder_path} is not a folder.")
        return None
    hashes = hash_folder(folder_path, skip=baseline_file)
    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)
    print(f"[+] Baseline saved for {len(hashes)} files to {baseline_file}")
    return len(hashes)


def check_integrity(folder_path, baseline_file=BASELINE_FILE):
    """Compare the folder to the saved baseline.

    Prints the differences and returns {"added", "removed", "changed"} as sorted
    lists, or None when there is no baseline or the folder is wrong.
    """
    if not os.path.isdir(folder_path):
        print(f"[!] {folder_path} is not a folder.")
        return None
    if not os.path.isfile(baseline_file):
        print(f"[!] No baseline found at {baseline_file}. Run 'save baseline' first.")
        return None

    with open(baseline_file, encoding="utf-8") as f:
        old_hashes = json.load(f)
    new_hashes = hash_folder(folder_path, skip=baseline_file)

    old_paths, new_paths = set(old_hashes), set(new_hashes)
    result = {
        "added": sorted(new_paths - old_paths),
        "removed": sorted(old_paths - new_paths),
        "changed": sorted(p for p in old_paths & new_paths if old_hashes[p] != new_hashes[p]),
    }

    if not any(result.values()):
        print("[+] No changes detected, everything matches the baseline.")
        return result

    for path in result["added"]:
        print(f"  [ADDED]   {path}")
    for path in result["removed"]:
        print(f"  [REMOVED] {path}")
    for path in result["changed"]:
        print(f"  [CHANGED] {path}")
    return result
