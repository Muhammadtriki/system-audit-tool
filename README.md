# System Audit Tool

A command-line tool that checks the health and exposure of a computer: CPU, memory, disk, busiest processes, startup programs, firewall, open ports, website security headers, file integrity and risky file permissions.

It reads information. The only things it changes are the report files it writes, a file you choose to download, and a process you confirm you want to stop.

## Features

- Full system report (CPU, RAM, disk, top processes, network interfaces, active connections), saved to `logs/`
- Port sweep of common ports with banner grabbing
- DNS lookup and HTTP security header check (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Installed software list and startup program audit (Windows registry Run keys and Startup folder, Linux systemd services and cron)
- Firewall status
- Live bandwidth monitor
- Local network device discovery (ARP scan, optional)
- File integrity checker: save a baseline of file hashes, then see what was changed, added or removed
- Sensitive file exposure check: finds SSH keys, AWS credentials and stray `.env` files and checks their permissions
- Export the report as text or HTML

## Install

```
git clone https://github.com/Muhammadtriki/system-audit-tool
cd system-audit-tool
pip install -r requirements.txt
```

Python 3 (tested with 3.13). `scapy` is only needed for the ARP scan.

## Use

Open the interactive menu:

```
python -m system_audit
```

Or run one check directly:

```
python -m system_audit --report
python -m system_audit --scan 127.0.0.1
python -m system_audit --resolve example.com
python -m system_audit --firewall
python -m system_audit --bandwidth
```

Some checks show more with admin or root rights, such as the firewall rules and the full list of network connections.

## Use it responsibly

Port scans and ARP scans are normal tools in IT and security work, but scanning a computer or network you do not own, or do not have permission to test, can be illegal. This tool prints a warning before every scan and asks you to confirm permission for anything other than your own computer. Only use it on your own machines and networks, or where you have written permission.

## Safety design

- **No surprises when stopping a process.** It shows exactly which processes match and asks for a yes. Names under three characters are refused, and core system processes, the tool itself and its parent are never offered.
- **Downloads are never run.** Only `https://` links are accepted, the file gets a safe name and is never overwritten, and the tool shows the SHA256 hash so you can compare it with the publisher's. It does not open or execute the file.
- **Credential checks never read secrets.** The exposure check looks at where sensitive files are and how they are protected. It never opens them.
- **Reports are escaped.** Names that come from the system, such as process names, are escaped in the HTML export so they cannot break the page.
- **Installed software is read from the registry** on Windows, not through `Win32_Product`, which is slow and can trigger Windows Installer repair checks.

## Privacy

Reports in `logs/` and the integrity baseline contain your username, IP addresses and file paths. They are listed in `.gitignore` so they are not uploaded by accident. Blur or remove personal details before sharing a screenshot.

## Platform support

Built for Windows and Linux. The automated tests run on Linux, and the Windows-only code (registry reads) is tested with a stand-in for the Windows registry. On macOS the system report works, and the Windows and Linux specific checks say they are not implemented.

## Project layout

```
system_audit/
  cli.py          menu and command-line flags
  system_info.py  privileges, CPU, memory, disk, processes, software, startup, firewall
  network.py      ports, banners, DNS, headers, interfaces, connections, bandwidth, ARP
  processes.py    finding and stopping processes safely
  integrity.py    file hashing and baseline comparison
  downloads.py    safe download with SHA256
  exposure.py     sensitive file permission checks
  reports.py      building and exporting reports
tests/            automated tests
```

## Run the tests

```
python -m unittest
```

The tests only touch your own machine (`127.0.0.1`) and temporary files.
