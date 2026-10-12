"""Network checks: ports, banners, DNS, security headers, interfaces, connections,
bandwidth and local device discovery.

Only point the scanning functions at machines and networks you own or have
permission to test.
"""

import ipaddress
import socket
import time

import psutil

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}

IMPORTANT_HEADERS = [
    "Strict-Transport-Security", "X-Frame-Options",
    "Content-Security-Policy", "X-Content-Type-Options",
]

PERMISSION_WARNING = "[!] Only scan machines and networks you own or have permission to test."


# ------------------------------------------------------------------------------
# Permission check before scanning
# ------------------------------------------------------------------------------
def is_loopback(address):
    """True for this computer's own address (localhost, 127.x.x.x, ::1)."""
    if address.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(address.strip()).is_loopback
    except ValueError:
        return False


def confirm_permission(target, ask=None):
    """Show the warning, and for anything other than this computer, ask for a yes."""
    ask = ask or input
    print(PERMISSION_WARNING)
    if is_loopback(target):
        return True
    answer = ask(f"Do you own {target} or have permission to scan it? (yes/no): ")
    return answer.strip().lower() == "yes"


# ------------------------------------------------------------------------------
# Ports and banners
# ------------------------------------------------------------------------------
def check_tcp_port(target_ip="127.0.0.1", port=80, timeout=2):
    """True if the port accepts a connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target_ip, port)) == 0
    except (OSError, OverflowError):
        return False


def scan_common_ports(target_ip="127.0.0.1", timeout=1, ports=None):
    """Return (port, service) for each port in the list that accepts a connection."""
    ports = COMMON_PORTS if ports is None else ports
    return [(port, service) for port, service in ports.items()
            if check_tcp_port(target_ip, port, timeout=timeout)]


def grab_banner(ip, port, timeout=2):
    """Connect and read whatever greeting the service sends."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except socket.timeout:
                banner = ""
        return banner or "(open, but no banner sent)"
    except OSError:
        return "(no response / connection refused)"


# ------------------------------------------------------------------------------
# DNS and HTTP security headers
# ------------------------------------------------------------------------------
def resolve_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def check_security_headers(url):
    if not HAS_REQUESTS:
        return "[!] The 'requests' library isn't installed. Run: pip install requests"
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as error:
        return f"[!] Could not reach {url}: {error}"
    results = [f"  {'[OK]' if header in response.headers else '[MISSING]'} {header}"
               for header in IMPORTANT_HEADERS]
    return f"Status code: {response.status_code}\n" + "\n".join(results)


# ------------------------------------------------------------------------------
# Interfaces, connections and bandwidth
# ------------------------------------------------------------------------------
def get_network_interfaces():
    interfaces = {}
    for name, address_list in psutil.net_if_addrs().items():
        ip_addresses = [a.address for a in address_list if a.family == socket.AF_INET]
        if ip_addresses:
            interfaces[name] = ip_addresses
    return interfaces


def get_active_connections():
    active = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("LISTEN", "ESTABLISHED"):
                continue
            process_name = "Unknown"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "Access Denied"
            active.append({
                "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                "status": conn.status,
                "pid": conn.pid or "N/A",
                "process": process_name,
            })
    except psutil.AccessDenied:
        print("  [!] Note: run with elevated/root rights to see all system sockets.")
    return active


def measure_bandwidth(interval=1.0):
    """Compare network byte counters `interval` seconds apart to get the current speed."""
    before = psutil.net_io_counters()
    time.sleep(interval)
    after = psutil.net_io_counters()
    return {
        "upload_kbps": (after.bytes_sent - before.bytes_sent) / interval / 1024,
        "download_kbps": (after.bytes_recv - before.bytes_recv) / interval / 1024,
    }


# ------------------------------------------------------------------------------
# Local device discovery (ARP scan)
# Needs: pip install scapy, and admin/root rights.
# ------------------------------------------------------------------------------
def arp_scan(ip_range="192.168.1.0/24"):
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        return "[!] scapy not installed. Run: pip install scapy (and run as admin/root)."
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        answered = srp(packet, timeout=2, verbose=False)[0]
        return [{"ip": reply.psrc, "mac": reply.hwsrc} for _, reply in answered]
    except Exception as error:
        return f"[!] ARP scan failed (often needs admin/root rights): {error}"
