import json
import socketserver
import threading
import subprocess
import unittest

import netwatch


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(16)
        except Exception:
            return


def start_test_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class NetwatchTests(unittest.TestCase):
    def test_parse_ports_range_and_single(self):
        ports = netwatch.parse_ports("22,80-82")
        self.assertEqual(ports, [22, 80, 81, 82])

    def test_expand_targets_cidr_and_range(self):
        cidr_targets = netwatch.expand_targets("192.168.1.0/30")
        self.assertEqual(cidr_targets, ["192.168.1.1", "192.168.1.2"])

        range_targets = netwatch.expand_targets("10.0.0.1-10.0.0.3")
        self.assertEqual(range_targets, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_run_scan_detects_open_and_closed_ports(self):
        server, thread = start_test_server()
        open_port = server.server_address[1]
        try:
            results = netwatch.run_scan(["127.0.0.1"], [open_port, 65000], timeout=0.5, threads=2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        result_by_port = {r.port: r for r in results}
        self.assertTrue(result_by_port[open_port].open)
        self.assertFalse(result_by_port[65000].open)

    def test_cli_json_output(self):
        server, thread = start_test_server()
        open_port = server.server_address[1]
        cmd = [
            "python",
            "netwatch.py",
            "127.0.0.1",
            "-p",
            f"{open_port},65001",
            "--timeout",
            "0.5",
            "--threads",
            "2",
            "--json",
        ]
        try:
            output = subprocess.check_output(cmd, text=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        data = json.loads(output)
        ports = {entry["port"]: entry for entry in data}
        self.assertTrue(ports[open_port]["open"])
        self.assertFalse(ports[65001]["open"])


if __name__ == "__main__":
    unittest.main()
