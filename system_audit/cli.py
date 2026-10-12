"""Command-line interface: an interactive menu, or flags that run one check directly."""

import argparse

from . import __version__
from .downloads import download_file
from .exposure import check_sensitive_exposure
from .integrity import check_integrity, save_baseline
from .network import (
    arp_scan,
    check_security_headers,
    confirm_permission,
    grab_banner,
    measure_bandwidth,
    resolve_host,
    scan_common_ports,
)
from .processes import stop_process_by_name
from .reports import export_report_html, run_full_report
from .system_info import get_firewall_status, get_installed_software, get_startup_programs

MENU_WIDTH = 55

MENU_ITEMS = [
    ("1", "Full system report (auto-logged to logs/)"),
    ("2", "Port sweep + banner grab on a target"),
    ("3", "Resolve a hostname to an IP"),
    ("4", "Check a URL's security headers"),
    ("5", "List installed software"),
    ("6", "Local network device discovery (ARP scan)"),
    ("7", "Download a file and show its SHA256 (https only)"),
    ("8", "Stop a running process by name"),
    ("9", "Startup / autorun program audit"),
    ("10", "Firewall status"),
    ("11", "Bandwidth monitor"),
    ("12", "File integrity: save baseline"),
    ("13", "File integrity: check against baseline"),
    ("14", "Sensitive file exposure check (permissions only)"),
    ("15", "Export last full report as HTML"),
    ("16", "Exit"),
]


def print_menu():
    print("\n" + "=" * MENU_WIDTH)
    print("   SYSTEM AUDIT TOOL")
    print("=" * MENU_WIDTH)
    for number, label in MENU_ITEMS:
        print(f"  {number + '.':<4}{label}")


def port_sweep(target):
    """Scan the common ports on a target, after the permission check."""
    if not confirm_permission(target):
        print("Cancelled, nothing was scanned.")
        return
    open_ports = scan_common_ports(target)
    if not open_ports:
        print("No common ports found open.")
    for port, service in open_ports:
        print(f"  Port {port} ({service}) OPEN - banner: {grab_banner(target, port)}")


def device_discovery(ip_range):
    if not confirm_permission(ip_range):
        print("Cancelled, nothing was scanned.")
        return
    result = arp_scan(ip_range)
    if isinstance(result, str):
        print(result)
    else:
        for device in result:
            print(f"  {device['ip']}  {device['mac']}")


def export_last_report(last_report):
    if not last_report:
        print("Run the full report first (option 1).")
        return
    destination = input("Destination path (e.g. E:\\report.html or /media/usb/report.html): ").strip()
    try:
        export_report_html(last_report, destination)
    except OSError as error:
        print(f"[!] Could not save the report: {error}")


def main():
    last_report = None

    while True:
        print_menu()
        choice = input("\nChoose an option (1-16): ").strip()

        if choice == "1":
            last_report = run_full_report()

        elif choice == "2":
            port_sweep(input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1")

        elif choice == "3":
            host = input("Hostname to resolve: ").strip()
            print(f"  {host} -> {resolve_host(host) or 'could not resolve'}")

        elif choice == "4":
            print(check_security_headers(input("URL to check: ").strip()))

        elif choice == "5":
            for line in get_installed_software():
                print(" ", line)

        elif choice == "6":
            device_discovery(input("IP range (default 192.168.1.0/24): ").strip() or "192.168.1.0/24")

        elif choice == "7":
            download_file(input("URL to download from (https only): ").strip())

        elif choice == "8":
            stop_process_by_name(input("Process name to stop (at least 3 characters): ").strip())

        elif choice == "9":
            for entry in get_startup_programs():
                print(" ", entry)

        elif choice == "10":
            print(get_firewall_status())

        elif choice == "11":
            print("[*] Measuring for 2 seconds...")
            bandwidth = measure_bandwidth(interval=2.0)
            print(f"  Upload:   {bandwidth['upload_kbps']:.1f} KB/s")
            print(f"  Download: {bandwidth['download_kbps']:.1f} KB/s")

        elif choice == "12":
            save_baseline(input("Folder to baseline: ").strip())

        elif choice == "13":
            check_integrity(input("Folder to check: ").strip())

        elif choice == "14":
            scan_root = input("Folder to scan for stray .env files (default .): ").strip() or "."
            for finding in check_sensitive_exposure(scan_root):
                print(" ", finding)

        elif choice == "15":
            export_last_report(last_report)

        elif choice == "16":
            print("Goodbye.")
            break

        else:
            print("Invalid choice, pick a number 1-16.")


def parse_args_and_run(argv=None):
    """Run one check from the command line, or open the menu when no flag is given."""
    parser = argparse.ArgumentParser(
        prog="system_audit",
        description="System audit tool: read-only checks of this computer and basic network tests.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--report", action="store_true", help="run the full system report")
    parser.add_argument("--scan", metavar="IP", help="port sweep + banner grab against an IP you have permission to scan")
    parser.add_argument("--resolve", metavar="HOST", help="resolve a hostname to an IP")
    parser.add_argument("--firewall", action="store_true", help="show firewall status")
    parser.add_argument("--bandwidth", action="store_true", help="measure current bandwidth")
    args = parser.parse_args(argv)

    if args.report:
        run_full_report()
    elif args.scan:
        port_sweep(args.scan)
    elif args.resolve:
        print(resolve_host(args.resolve) or "could not resolve")
    elif args.firewall:
        print(get_firewall_status())
    elif args.bandwidth:
        bandwidth = measure_bandwidth(2.0)
        print(f"Upload: {bandwidth['upload_kbps']:.1f} KB/s | Download: {bandwidth['download_kbps']:.1f} KB/s")
    else:
        main()
