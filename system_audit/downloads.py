"""Download a file and show its SHA256 hash. The file is never opened or run."""

import http.client
import os
import urllib.parse
import urllib.request

from .integrity import sha256_of_file

MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MB
CHUNK_SIZE = 8192


def filename_from_url(url):
    """A safe local file name taken from the end of the URL path."""
    path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
    name = os.path.basename(path)
    name = "".join(char for char in name if char.isalnum() or char in "._-").lstrip(".")
    return name or "downloaded_file"


def unique_path(directory, filename):
    """directory/filename, or with ' (1)', ' (2)'... added if the name is taken."""
    stem, suffix = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    number = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{stem} ({number}){suffix}")
        number += 1
    return candidate


def save_stream(stream, destination, max_bytes=MAX_DOWNLOAD_BYTES):
    """Copy a readable stream to a file. A file over the size limit is removed again."""
    written = 0
    try:
        with open(destination, "wb") as out:
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise ValueError("the file is larger than the allowed limit")
                out.write(chunk)
    except Exception:
        if os.path.exists(destination):
            os.remove(destination)
        raise
    return written


def download_file(url, directory=None, ask=None):
    """Download after one confirmation. Returns the saved path, or None."""
    ask = ask or input
    if urllib.parse.urlparse(url).scheme != "https":
        print("[!] Only https:// links are allowed.")
        return None

    answer = ask(f"About to download from:\n  {url}\nOnly do this if you trust the source. Continue? (yes/no): ")
    if answer.strip().lower() != "yes":
        print("Cancelled, nothing downloaded.")
        return None

    destination = unique_path(directory or os.getcwd(), filename_from_url(url))
    print(f"[*] Downloading from: {url}")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            save_stream(response, destination)
    except (OSError, ValueError, http.client.HTTPException) as error:
        print(f"[!] Download failed: {error}")
        return None

    print(f"[+] Saved to: {destination}")
    print(f"[*] SHA256: {sha256_of_file(destination)}")
    print("[i] The file was NOT opened or run. Compare the hash with the one the publisher lists before using it.")
    return destination
