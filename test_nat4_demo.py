"""Run: python3 -B -m unittest discover -v (from the project root).

All network traffic stays on loopback, including the independent process tests.
"""

import os
from pathlib import Path
import queue
import re
import selectors
import socket
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace

import nat4_demo as n

HERE = Path(__file__).resolve().parent
PYTHON = [sys.executable, "-B", "-u", str(HERE / "nat4_demo.py")]


def read_udp(sock, timeout=1):
    with selectors.DefaultSelector() as selector:
        selector.register(sock, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if selector.select(max(0, deadline - time.monotonic())):
                item = n.udp_recv(sock)
                if item:
                    return item
    return None


def read_endpoint(endpoint, timeout=1):
    with selectors.DefaultSelector() as selector:
        selector.register(endpoint.sock, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if selector.select(max(0, deadline - time.monotonic())):
                item = endpoint.recv()
                if item:
                    return item
    return None


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition timed out")


class Child(n.Managed):
    def __init__(self, argv):
        self.proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    def server_address(self):
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: lines.put(self.proc.stdout.readline()), daemon=True)
        reader.start()
        line = lines.get(timeout=8)
        reader.join(1)
        match = re.search(r"TCP=(127\.0\.0\.1:\d+)", line)
        if not match:
            raise AssertionError("server not ready: " + line)
        return match.group(1)

    def result(self):
        output, _ = self.proc.communicate(timeout=15)
        if self.proc.returncode != 0 or "DIRECT_OK" not in output or "VERIFIED" not in output:
            raise AssertionError("peer exit={}\n{}".format(self.proc.returncode, output))
        return output

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.communicate(timeout=3)
        if self.proc.stdout:
            self.proc.stdout.close()


def process_pair(server_command, a_command, b_command):
    with ExitStack() as stack:
        server = stack.enter_context(Child(server_command + [
            "server", "--bind", "127.0.0.1:0", "--rounds", "2", "--round-ms", "700"]))
        target = server.server_address()
        peers = [stack.enter_context(Child(command + [
            "peer", "--server", target, "--room", "process-test", "--id", peer_id,
            "--strategy", "predict", "--pps", "200"]))
                 for command, peer_id in ((a_command, "alice"), (b_command, "bob"))]
        return [peer.result() for peer in peers]


class NatSemanticsTests(unittest.TestCase):
    def test_mapping_depends_on_both_internal_and_remote_ip_and_port(self):
        with ExitStack() as stack:
            nat = stack.enter_context(n.Nat(n.NatConfig("127.65.1.2")))
            endpoints = [stack.enter_context(n.Endpoint(nat.gateway)) for _ in range(2)]
            remote1 = stack.enter_context(n.udp_bind(("127.65.1.10", 0)))
            remote2 = stack.enter_context(n.udp_bind(("127.65.1.10", 0)))
            remote3 = stack.enter_context(n.udp_bind(("127.65.1.11", remote1.getsockname()[1])))

            def observed(endpoint, remote):
                endpoint.send("request", remote.getsockname())
                data, source = read_udp(remote)
                self.assertEqual(data, b"request")
                return source

            first = observed(endpoints[0], remote1)
            self.assertEqual(first, observed(endpoints[0], remote1))
            sources = {first, observed(endpoints[0], remote2),
                       observed(endpoints[0], remote3), observed(endpoints[1], remote1)}
            self.assertEqual(len(sources), 4)
            self.assertEqual(nat.stats.mappings, 4)
            self.assertIsNone(nat.error)

    def test_filter_requires_exact_remote_ip_and_port(self):
        with ExitStack() as stack:
            nat = stack.enter_context(n.Nat(n.NatConfig("127.65.2.2")))
            endpoint = stack.enter_context(n.Endpoint(nat.gateway))
            allowed = stack.enter_context(n.udp_bind(("127.65.2.10", 0)))
            wrong_port = stack.enter_context(n.udp_bind(("127.65.2.10", 0)))
            wrong_ip = stack.enter_context(n.udp_bind(("127.65.2.11", allowed.getsockname()[1])))
            endpoint.send("open", allowed.getsockname())
            _, public = read_udp(allowed)
            for remote in (wrong_port, wrong_ip):
                remote.sendto(b"blocked", public)
            wait_for(lambda: nat.stats.filtered == 2)
            self.assertIsNone(read_endpoint(endpoint, 0.08))
            allowed.sendto(b"accepted", public)
            self.assertEqual(read_endpoint(endpoint), ("accepted", allowed.getsockname()))
            self.assertIsNone(nat.error)

    def test_expired_mapping_does_not_accept_even_the_right_source(self):
        with ExitStack() as stack:
            nat = stack.enter_context(n.Nat(n.NatConfig("127.65.3.2", ttl_ms=150)))
            endpoint = stack.enter_context(n.Endpoint(nat.gateway))
            remote = stack.enter_context(n.udp_bind(("127.65.3.10", 0)))
            endpoint.send("open", remote.getsockname())
            _, public = read_udp(remote)
            wait_for(lambda: nat.stats.expired == 1)
            remote.sendto(b"too-late", public)
            self.assertIsNone(read_endpoint(endpoint, 0.15))
            self.assertEqual(nat.stats.inbound, 0)

    def test_capacity_exhaustion_drops_instead_of_reusing_a_live_mapping(self):
        with ExitStack() as stack:
            nat = stack.enter_context(n.Nat(n.NatConfig("127.65.4.2", low=25000, high=25000)))
            endpoint = stack.enter_context(n.Endpoint(nat.gateway))
            a = stack.enter_context(n.udp_bind(("127.65.4.10", 0)))
            b = stack.enter_context(n.udp_bind(("127.65.4.10", 0)))
            endpoint.send("first", a.getsockname())
            self.assertIsNotNone(read_udp(a))
            endpoint.send("second", b.getsockname())
            wait_for(lambda: nat.stats.capacity_drops == 1)
            self.assertIsNone(read_udp(b, 0.08))
            self.assertEqual(nat.stats.mappings, 1)


class ProofTests(unittest.TestCase):
    def test_replayed_wrong_payload_or_out_of_context_pongs_are_not_counted(self):
        cfg = n.PeerConfig(("127.0.0.1", 1), "room", "alice")
        remote = ("127.0.0.1", 20000)
        state = n.SocketState(nonce="challenge", remote=remote, pending={7: 1.0})
        good = n.Packet("PONG", "session", "room", "bob", 0, "challenge", 7, "hello-from-alice")
        bad = [replace(good, **change) for change in (
            {"session": "old"}, {"room": "other"}, {"sender": "mallory"},
            {"round": 1}, {"nonce": "wrong"}, {"seq": 8}, {"body": "wrong"})]
        for packet in bad:
            state.receive(packet.encode(), remote, cfg, "session", "bob", 0, 2.0)
        state.receive(good.encode(), (remote[0], remote[1] + 1), cfg, "session", "bob", 0, 2.0)
        self.assertEqual(state.pongs, 0)
        self.assertIn(7, state.pending)
        state.receive(good.encode(), remote, cfg, "session", "bob", 0, 2.0)
        state.receive(good.encode(), remote, cfg, "session", "bob", 0, 3.0)
        self.assertEqual(state.pongs, 1)
        self.assertEqual(state.total_rtt, 1.0)

    def test_coordinator_success_message_alone_is_not_proof(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)

            def fake_coordinator():
                client, _ = listener.accept()
                with n.Control(client) as control:
                    control.recv()
                    control.send("MATCH session A bob 1 700 30000,30001,30002")
                    control.send("DONE OK")

            with ThreadPoolExecutor(max_workers=1) as pool:
                task = pool.submit(fake_coordinator)
                result = n.run_peer(n.PeerConfig(listener.getsockname(), "room", "alice"))
                task.result(timeout=5)
            self.assertFalse(result.connected)
            self.assertEqual(result.attempt.pongs, 0)

    def test_coordinator_udp_only_answers_address_probes(self):
        with n.Server(("127.0.0.1", 0)) as server, n.Endpoint() as endpoint:
            self.assertEqual(n.probe(endpoint, server.probes[0])[1], endpoint.sock.getsockname()[1])
            endpoint.send(n.Packet("PING", "s", "r", "alice", 0, "n", 1, "hello-from-alice").encode(),
                          server.probes[0])
            self.assertIsNone(read_endpoint(endpoint, 0.1))
            self.assertEqual(server.probe_replies, 1)


class LabTests(unittest.TestCase):
    def test_sequential_nat4_connects(self):
        result = n.run_lab("predict")
        self.assertTrue(result.passed)
        self.assertTrue(result.a.connected and result.b.connected)
        self.assertGreaterEqual(min(result.a.attempt.pongs, result.b.attempt.pongs), 3)
        self.assertEqual(result.mappings, 8)

    def test_known_small_random_pool_connects_with_strict_filtering(self):
        result = n.run_lab("random-small")
        self.assertTrue(result.passed)
        self.assertTrue(result.a.connected and result.b.connected)
        self.assertGreater(result.filtered, 0)
        self.assertEqual(result.capacity_drops, 0)

    def test_full_random_pool_misses_with_this_seed_and_budget(self):
        result = n.run_lab("random-full")
        self.assertTrue(result.passed)
        self.assertFalse(result.a.connected or result.b.connected)

    def test_prediction_on_random_nat_misses(self):
        result = n.run_lab("predict-on-random")
        self.assertTrue(result.passed)
        self.assertFalse(result.a.connected or result.b.connected)


class ProcessTests(unittest.TestCase):
    def test_three_independent_python_processes(self):
        process_pair(PYTHON, PYTHON, PYTHON)


    def test_python_server_with_peers_behind_two_strict_nats(self):
        with ExitStack() as stack:
            server = stack.enter_context(Child(PYTHON + ["server", "--bind", "127.0.0.1:0",
                                                       "--rounds", "2", "--round-ms", "700"]))
            target = n.address(server.server_address())
            nats = [stack.enter_context(n.Nat(n.NatConfig("127.65.5.{}".format(last)))) for last in (2, 3)]
            configs = [n.PeerConfig(target, "strict-nat", peer_id, gateway=nat.gateway)
                       for peer_id, nat in zip(("alice", "bob"), nats)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(n.run_peer, cfg) for cfg in configs]
                results = [f.result(timeout=15) for f in futures]
            self.assertTrue(all(r.connected and r.attempt.pongs >= 3 for r in results))
            self.assertTrue(all(nat.error is None for nat in nats))


if __name__ == "__main__":
    unittest.main(verbosity=2)
