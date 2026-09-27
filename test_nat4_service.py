"""Real-process service lifecycle, dynamic peers, retries and parent EOF tests."""

import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest

import nat4_demo as n
import nat4_service as service
from test_nat4_tunnel import TestKeys, WebDavHandler, webdav_round_trip
from http.server import ThreadingHTTPServer


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = TestKeys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nat4-service-")
        self.config = Path(self.temporary.name) / "service.json"
        self.process = None
        self.lines = queue.Queue()

    def tearDown(self):
        if self.process:
            if self.process.poll() is None:
                self.process.stdin.close()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            for stream in (self.process.stdin, self.process.stdout):
                stream.close()
        resolved = Path(self.temporary.name).resolve()
        assert resolved.parent == Path(tempfile.gettempdir()).resolve()
        assert resolved.name.startswith("nat4-service-")
        self.temporary.cleanup()

    def write(self, peers):
        self.config.write_text(json.dumps({"peers": peers, "retry": {
            "initial_seconds": 0.1, "max_seconds": 0.2}}), encoding="utf-8")

    def start(self):
        script = Path(__file__).resolve().with_name("nat4_tunnel.py")
        self.process = subprocess.Popen([sys.executable, "-B", "-u", str(script), "daemon",
                                         "--config", str(self.config), "--control-stdio"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, bufsize=1,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        def read():
            for line in self.process.stdout:
                self.lines.put(json.loads(line))
        threading.Thread(target=read, daemon=True).start()
        self.wait("started")

    def wait(self, event, **fields):
        for _ in range(100):
            value = self.lines.get(timeout=20)
            if value["event"] == event and all(value.get(key) == expected for key, expected in fields.items()):
                return value
        self.fail("missing service event " + event)

    def command(self, command):
        self.process.stdin.write(json.dumps({"id": command, "command": command}) + "\n")
        self.process.stdin.flush()

    def peer(self, role, server, **extra):
        return dict(name=role, role=role, server=server, room="service-test",
                    keys=str(self.keys.path / ("nas" if role == "serve" else "client")), **extra)

    def test_empty_service_stays_running_and_parent_eof_stops_it(self):
        self.write([])
        self.start()
        self.command("status")
        self.assertEqual(self.wait("status")["peers"], [])
        self.process.stdin.close()
        self.wait("stopped")
        self.assertEqual(self.process.wait(timeout=5), 0)

    def test_unavailable_coordinator_retries_without_exiting_daemon(self):
        with n.Server(("127.0.0.1", 0)) as coordinator:
            address = n.addr_text(coordinator.address)
        self.write([self.peer("connect", address, listen="127.0.0.1:0")])
        self.start()
        first = self.wait("peer_starting")
        retry = self.wait("peer_retry")
        self.assertLessEqual(retry["retry_seconds"], 0.2)
        second = self.wait("peer_starting")
        self.assertNotEqual(first["pid"], second["pid"])
        self.assertIsNone(self.process.poll())

    def test_reload_connects_late_peer_and_invalid_reload_preserves_tunnels(self):
        http = ThreadingHTTPServer(("127.0.0.1", 0), WebDavHandler)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        try:
            with n.Server(("127.0.0.1", 0), n.ServerConfig(rounds=2, round_ms=700)) as coordinator:
                address = n.addr_text(coordinator.address)
                nas = self.peer("serve", address, target=n.addr_text(http.server_address))
                self.write([nas])
                self.start()
                original = self.wait("peer_starting", name="serve")
                self.write([nas, self.peer("connect", address, listen="127.0.0.1:0")])
                self.command("reload")
                self.wait("reloaded")
                ready = self.wait("peer_ready", name="connect")
                port = n.address(ready["endpoint"])[1]
                self.assertEqual(webdav_round_trip(port, "service-file", b"service-data" * 8192), 98304)
                self.config.write_text('{"peers":[{"name":"invalid"}]}', encoding="utf-8")
                self.command("reload")
                self.wait("command_failed")
                self.command("status")
                peers = self.wait("status")["peers"]
                self.assertEqual(next(p["pid"] for p in peers if p["name"] == "serve"), original["pid"])
                self.assertEqual(webdav_round_trip(port, "still-alive", b"ok"), 2)
                self.write([])
                self.command("reload")
                self.wait("reloaded")
                self.command("status")
                self.assertEqual(self.wait("status")["peers"], [])
        finally:
            http.shutdown()
            http.server_close()

    def test_invalid_retry_configuration_is_rejected_before_spawn(self):
        for value in (False, -1, float("nan"), 1000):
            self.config.write_text(json.dumps({"retry": {"initial_seconds": value}}), encoding="utf-8")
            with self.subTest(value=value), self.assertRaises(ValueError):
                service.load_config(self.config)


if __name__ == "__main__":
    unittest.main()
