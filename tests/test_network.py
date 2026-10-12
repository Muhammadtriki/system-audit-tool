import importlib.util
import socket
import threading
import unittest
from unittest.mock import patch

from system_audit import network


class LocalServer:
    """A throwaway TCP server on 127.0.0.1 that optionally sends a greeting."""

    def __init__(self, banner=None):
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            if self.banner:
                conn.sendall(self.banner)
            conn.close()

    def close(self):
        self.sock.close()


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeResponse:
    status_code = 200
    headers = {"Strict-Transport-Security": "max-age=1"}


class NetworkTests(unittest.TestCase):
    def test_open_and_closed_ports(self):
        server = LocalServer()
        self.addCleanup(server.close)
        self.assertTrue(network.check_tcp_port("127.0.0.1", server.port, timeout=2))
        self.assertFalse(network.check_tcp_port("127.0.0.1", unused_port(), timeout=1))

    def test_scan_common_ports_finds_only_open_ones(self):
        server = LocalServer()
        self.addCleanup(server.close)
        ports = {server.port: "TEST", unused_port(): "CLOSED"}
        self.assertEqual(network.scan_common_ports("127.0.0.1", timeout=1, ports=ports), [(server.port, "TEST")])

    def test_banner_is_read(self):
        server = LocalServer(banner=b"220 hello banner\r\n")
        self.addCleanup(server.close)
        self.assertEqual(network.grab_banner("127.0.0.1", server.port), "220 hello banner")

    def test_open_port_without_a_banner(self):
        server = LocalServer()
        self.addCleanup(server.close)
        # the server closes right away, so an empty read means "open, but no banner"
        self.assertEqual(network.grab_banner("127.0.0.1", server.port, timeout=1), "(open, but no banner sent)")

    def test_banner_on_a_closed_port(self):
        self.assertEqual(network.grab_banner("127.0.0.1", unused_port(), timeout=1),
                         "(no response / connection refused)")

    def test_resolve_host(self):
        self.assertEqual(network.resolve_host("localhost"), "127.0.0.1")
        self.assertIsNone(network.resolve_host("no-such-host.invalid"))

    def test_loopback_detection(self):
        for address in ("localhost", "127.0.0.1", "127.5.5.5", "::1"):
            self.assertTrue(network.is_loopback(address), address)
        for address in ("192.168.1.5", "8.8.8.8", "192.168.1.0/24", "example.com"):
            self.assertFalse(network.is_loopback(address), address)

    def test_permission_is_not_asked_for_this_computer(self):
        def fail_if_asked(prompt):
            raise AssertionError("should not ask")

        with patch("builtins.print"):
            self.assertTrue(network.confirm_permission("127.0.0.1", ask=fail_if_asked))

    def test_permission_is_asked_for_other_targets(self):
        with patch("builtins.print") as fake_print:
            self.assertTrue(network.confirm_permission("192.168.1.5", ask=lambda p: "yes"))
            self.assertFalse(network.confirm_permission("192.168.1.5", ask=lambda p: "no"))
            self.assertFalse(network.confirm_permission("192.168.1.5", ask=lambda p: ""))
        printed = " ".join(str(call.args[0]) for call in fake_print.call_args_list)
        self.assertIn("permission", printed)

    def test_security_headers_report(self):
        with patch.object(network.requests, "get", return_value=FakeResponse()) as fake_get:
            report = network.check_security_headers("example.com")
        self.assertEqual(fake_get.call_args.args[0], "https://example.com")
        self.assertIn("Status code: 200", report)
        self.assertIn("[OK] Strict-Transport-Security", report)
        self.assertIn("[MISSING] X-Frame-Options", report)

    def test_security_headers_when_the_site_is_unreachable(self):
        error = network.requests.ConnectionError("boom")
        with patch.object(network.requests, "get", side_effect=error):
            self.assertIn("Could not reach", network.check_security_headers("https://example.com"))

    def test_network_interfaces_structure(self):
        for name, addresses in network.get_network_interfaces().items():
            self.assertIsInstance(name, str)
            self.assertTrue(all(isinstance(address, str) for address in addresses))

    def test_active_connections_structure(self):
        with patch("builtins.print"):
            connections = network.get_active_connections()
        for conn in connections:
            self.assertIn(conn["status"], ("LISTEN", "ESTABLISHED"))

    def test_bandwidth_numbers(self):
        speed = network.measure_bandwidth(interval=0.2)
        self.assertGreaterEqual(speed["upload_kbps"], 0)
        self.assertGreaterEqual(speed["download_kbps"], 0)

    @unittest.skipIf(importlib.util.find_spec("scapy"), "scapy is installed")
    def test_arp_scan_explains_a_missing_scapy(self):
        self.assertIn("scapy not installed", network.arp_scan())


if __name__ == "__main__":
    unittest.main()
