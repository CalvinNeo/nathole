"""Local-only tunnel tests: loss/reorder, TLS authentication and WebDAV data.

Python 3.8+, no pip packages. OpenSSL is needed to generate temporary test keys.
Set NAT4_TEST_KEYS to reuse a previously generated test key directory.
"""

import asyncio
import base64
import contextlib
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack

import nat4_demo as n
import nat4_rudp as r
import nat4_tunnel as t


class LossyWire:
    def __init__(self):
        self.dropped = set()
        self.count = 0
        self.observed = bytearray()

    def __call__(self, send, data, target):
        self.count += 1
        self.observed.extend(data)
        _, kind, _, number, seq, _, _ = r.HEADER.unpack(data[:r.HEADER.size])
        if kind == r.DATA and seq % 13 == 1 and seq not in self.dropped:
            self.dropped.add(seq)
            return
        if kind == r.ACK and number % 11 == 0:
            return
        loop = asyncio.get_running_loop()
        if number % 7 == 0:
            loop.call_later(0.015, send, data, target)
        else:
            send(data, target)
        if number % 17 == 0:
            loop.call_later(0.01, send, data, target)


def loopback_address(endpoint):
    return "127.0.0.1", endpoint.sock.getsockname()[1]


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.stack = ExitStack()
        self.channels = []

    async def asyncTearDown(self):
        for channel in self.channels:
            await channel.close()
        # Deliver delayed duplicate datagrams while transports still exist.
        await asyncio.sleep(0.03)
        self.stack.close()

    async def pair(self, hooks=(None, None), keys=None, gateways=(None, None), remotes=None, **options):
        keys = keys or (b"k" * 32, b"k" * 32)
        endpoints = [self.stack.enter_context(n.Endpoint(g)) for g in gateways]
        remotes = remotes or (loopback_address(endpoints[1]), loopback_address(endpoints[0]))
        for i in range(2):
            self.channels.append(await r.attach(endpoints[i], remotes[i], "test-session", str(i), str(1 - i),
                                                keys[i], i == 0, send_hook=hooks[i], **options))
        return self.channels

    async def test_bidirectional_bytes_survive_loss_reorder_duplicates_and_backpressure(self):
        faults = (LossyWire(), LossyWire())
        a, b = await self.pair(faults)
        await asyncio.gather(a.wait_ready(), b.wait_ready())
        contents = (bytes(range(256)) * 1024, secrets.token_bytes(280000))

        async def receive(channel, length):
            data = bytearray()
            while len(data) < length:
                data.extend(await channel.read())
                # Force receive-queue pressure while the other sender runs.
                if len(data) < 50000:
                    await asyncio.sleep(0.002)
            return bytes(data)

        jobs = [a.write(contents[0]), b.write(contents[1]),
                receive(b, len(contents[0])), receive(a, len(contents[1]))]
        results = await asyncio.wait_for(asyncio.gather(*jobs), 30)
        self.assertEqual(results[2:], list(contents))
        self.assertGreater(a.retransmissions + b.retransmissions, 0)
        self.assertGreater(a.rejected + b.rejected, 0)  # Replayed duplicates.
        self.assertLessEqual(max(len(a.reorder), len(b.reorder)), r.WINDOW)

    async def test_wrong_shared_key_never_authenticates(self):
        a, b = await self.pair(keys=(b"a" * 32, b"b" * 32))
        results = await asyncio.gather(a.wait_ready(0.5), b.wait_ready(0.5), return_exceptions=True)
        self.assertTrue(all(isinstance(x, TimeoutError) for x in results))
        self.assertFalse(a.ready.is_set() or b.ready.is_set())

    async def test_lost_peer_times_out_instead_of_leaving_a_hung_stream(self):
        a, b = await self.pair(keepalive=0.05, idle_timeout=0.5)
        await asyncio.gather(a.wait_ready(), b.wait_ready())
        # A silent network blackhole exercises the keepalive deadline. Closing
        # the peer socket instead may immediately return ICMP port-unreachable.
        b.send_hook = lambda send, data, target: None
        for _ in range(30):
            if a.error:
                break
            await asyncio.sleep(0.05)
        self.assertIsInstance(a.error, TimeoutError)
        with self.assertRaises(ConnectionError):
            await a.write(b"cannot-send")

    async def test_keepalive_preserves_strict_nat_mapping_while_idle(self):
        nat_a = self.stack.enter_context(n.Nat(n.NatConfig("127.66.1.2", ttl_ms=600)))
        nat_b = self.stack.enter_context(n.Nat(n.NatConfig("127.66.1.3", ttl_ms=600)))
        a, b = await self.pair(gateways=(nat_a.gateway, nat_b.gateway),
                               remotes=(("127.66.1.3", 20000), ("127.66.1.2", 20000)),
                               keepalive=0.15, idle_timeout=3)
        await asyncio.gather(a.wait_ready(), b.wait_ready())
        await asyncio.sleep(1.8)
        await a.write(b"still-the-same-mapping")
        self.assertEqual(await asyncio.wait_for(b.read(), 2), b"still-the-same-mapping")
        self.assertEqual(nat_a.stats.mappings + nat_b.stats.mappings, 2)
        self.assertEqual(nat_a.stats.expired + nat_b.stats.expired, 0)


class WebDavHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    files = {}
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def respond(self, status, data=b"", content_type="application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        with self.lock:
            self.files[self.path] = data
        self.respond(201)

    def do_GET(self):
        with self.lock:
            data = self.files[self.path]
        self.respond(200, data)

    def do_PROPFIND(self):
        self.respond(207, b'<d:multistatus xmlns:d="DAV:"><d:response/></d:multistatus>', "application/xml")


def webdav_round_trip(port, name, content):
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=30)) as connection:
        # A real HTTP/1.1 keep-alive connection carrying WebDAV methods.
        headers = {"Authorization": "Basic " + base64.b64encode(b"testuser:test-password").decode()}
        connection.request("PUT", "/" + name, body=content, headers=headers)
        response = connection.getresponse()
        assert response.status == 201
        response.read()
        connection.request("PROPFIND", "/", headers={"Depth": "1", **headers})
        response = connection.getresponse()
        assert response.status == 207 and b"multistatus" in response.read()
        connection.request("GET", "/" + name, headers=headers)
        response = connection.getresponse()
        downloaded = response.read()
        assert response.status == 200 and hashlib.sha256(downloaded).digest() == hashlib.sha256(content).digest()
        return len(downloaded)


class TestKeys:
    def __init__(self):
        self.temp = None
        if os.environ.get("NAT4_TEST_KEYS"):
            self.path = Path(os.environ["NAT4_TEST_KEYS"])
        else:
            self.temp = tempfile.TemporaryDirectory(prefix="nat4-test-")
            self.path = t.keygen(Path(self.temp.name) / "keys")

    def close(self):
        if self.temp:
            resolved = Path(self.temp.name).resolve()
            assert resolved.parent == Path(tempfile.gettempdir()).resolve()
            assert resolved.name.startswith("nat4-test-")
            self.temp.cleanup()


class ForwardingTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = TestKeys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    async def asyncSetUp(self):
        self.stack = ExitStack()
        self.tasks = []
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), WebDavHandler)
        self.http.daemon_threads = True
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.http_thread.start()

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.sleep(0.04)
        self.stack.close()
        await asyncio.get_running_loop().run_in_executor(None, self.http.shutdown)
        self.http.server_close()
        self.http_thread.join(2)

    async def tunnels(self, hooks=(None, None), target=None, server_context=None, client_context=None):
        endpoints = [self.stack.enter_context(n.Endpoint()) for _ in range(2)]
        nas_secret, nas_context = t.credentials(self.keys.path / "nas", True)
        pc_secret, pc_context = t.credentials(self.keys.path / "client", False)
        ready = [asyncio.Future(), asyncio.Future()]

        def mark(index, mux):
            if not ready[index].done():
                ready[index].set_result(mux)

        for i, secret, context in ((0, nas_secret, server_context or nas_context),
                                   (1, pc_secret, client_context or pc_context)):
            self.tasks.append(asyncio.create_task(t.run_tunnel(
                endpoints[i], loopback_address(endpoints[1 - i]), "webdav-test", str(i), str(1 - i),
                i == 0, secret, context, target=target or self.http.server_address,
                listen=("127.0.0.1", 0), on_ready=lambda mux, index=i: mark(index, mux),
                send_hook=hooks[i], keepalive=0.3, idle_timeout=3)))
        deadline = asyncio.get_running_loop().time() + 20
        while not all(future.done() for future in ready):
            for task in self.tasks:
                if task.done():
                    await task  # Surface handshake failure immediately.
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("tunnel startup timed out")
            await asyncio.sleep(0.01)
        return [future.result() for future in ready]

    async def test_webdav_upload_download_listing_concurrency_and_encryption_with_loss(self):
        faults = (LossyWire(), LossyWire())
        _, pc = await self.tunnels(faults)
        content = b"unique-private-webdav-payload-" * 8000
        loop = asyncio.get_running_loop()
        jobs = [loop.run_in_executor(None, webdav_round_trip, pc.listen[1], str(i), content + bytes([i]))
                for i in range(3)]
        self.assertEqual(await asyncio.wait_for(asyncio.gather(*jobs), 60), [len(content) + 1] * 3)
        for wire in faults:
            self.assertNotIn(b"unique-private-webdav-payload", wire.observed)
            self.assertNotIn(b"Authorization: Basic", wire.observed)
            self.assertGreater(len(wire.dropped), 0)

    async def test_tcp_half_close_delivers_request_then_response(self):
        async def reply_after_eof(reader, writer):
            try:
                request = await reader.read()
                writer.write(b"response:" + request)
                await writer.drain()
            finally:
                await t.close_writer(writer)

        server = await asyncio.start_server(reply_after_eof, "127.0.0.1", 0)
        try:
            _, pc = await self.tunnels(target=server.sockets[0].getsockname())
            reader, writer = await asyncio.open_connection(*pc.listen)
            writer.write(b"request-body")
            await writer.drain()
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"response:request-body")
            await t.close_writer(writer)
        finally:
            server.close()
            await server.wait_closed()

    async def test_refused_target_closes_only_that_stream(self):
        # A bound but non-listening TCP socket deterministically refuses connect.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            _, pc = await self.tunnels(target=unavailable.getsockname())
            reader, writer = await asyncio.open_connection(*pc.listen)
            try:
                with contextlib.suppress(ConnectionError):
                    self.assertEqual(await asyncio.wait_for(reader.read(1), 5), b"")
            finally:
                await t.close_writer(writer)
            self.assertTrue(all(not task.done() for task in self.tasks))

    async def test_untrusted_tls_certificate_is_rejected(self):
        # Keep the UDP secret correct, but remove trust in the private CA.
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        folder = self.keys.path / "client"
        client.load_cert_chain(str(folder / "cert.pem"), str(folder / "key.pem"))
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            await self.tunnels(client_context=client)
        errors = [task.exception() for task in self.tasks if task.done() and not task.cancelled()]
        self.assertTrue(any(isinstance(error, ssl.SSLError) for error in errors), errors)

    async def test_nas_requires_a_client_certificate(self):
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.load_verify_locations(cafile=str(self.keys.path / "client" / "ca.pem"))
        with self.assertRaises((ssl.SSLError, ConnectionError)):
            await self.tunnels(client_context=client)
        errors = [task.exception() for task in self.tasks if task.done() and not task.cancelled()]
        self.assertTrue(any(isinstance(error, ssl.SSLError) for error in errors), errors)


class CLIForwardingTests(unittest.TestCase):
    def test_real_coordinator_socket_handoff_and_webdav_three_processes(self):
        keys = TestKeys()
        http = ThreadingHTTPServer(("127.0.0.1", 0), WebDavHandler)
        http.daemon_threads = True
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        processes = []
        logs = []
        base = [sys.executable, "-B", "-u"]
        directory = Path(__file__).resolve().parent

        def child(command):
            process = subprocess.Popen(base + command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, bufsize=1,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            processes.append(process)
            lines = queue.Queue()
            log = []
            logs.append(log)

            def read():
                for line in process.stdout:
                    log.append(line)
                    lines.put(line)

            threading.Thread(target=read, daemon=True).start()
            return lines

        def wait_line(lines, needle):
            while True:
                line = lines.get(timeout=20)
                if needle in line:
                    return line

        try:
            server = child([str(directory / "nat4_demo.py"), "server", "--bind", "127.0.0.1:0",
                            "--round-ms", "700", "--rounds", "2"])
            target = wait_line(server, "TCP=").split("TCP=", 1)[1].split()[0]
            common = [str(directory / "nat4_tunnel.py")]
            nas = child(common + ["serve", "--server", target, "--keys", str(keys.path / "nas"),
                                  "--target", n.addr_text(http.server_address)])
            pc = child(common + ["connect", "--server", target, "--keys", str(keys.path / "client"),
                                 "--listen", "127.0.0.1:0"])
            wait_line(nas, "TUNNEL_READY")
            line = wait_line(pc, "TUNNEL_READY")
            local = n.address(line.split("listen=", 1)[1].split()[0])
            payload = secrets.token_bytes(1024 * 1024)
            self.assertEqual(webdav_round_trip(local[1], "cli-file", payload), len(payload))
            self.assertTrue(all(process.poll() is None for process in processes))
        except BaseException:
            for log in logs:
                print("".join(log))
            raise
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
                process.stdout.close()
            http.shutdown()
            http.server_close()
            thread.join(2)
            keys.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
