#!/usr/bin/env python3
"""Authenticated TLS TCP forwarding over a punched UDP socket. Python 3.8+.

Run `keygen` once on a PC with OpenSSL, copy the nas keys to the NAS, then run
`serve` on the NAS and `connect` on the PC. The existing coordinator is unchanged.
"""

import argparse
import asyncio
import contextlib
import ipaddress
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys

import nat4_demo as n
import nat4_rudp as rudp

FRAME = struct.Struct("!BII")
OPEN, OPEN_OK, DATA, FIN, RESET, CREDIT = range(1, 7)
BLOCK = 16384
CREDIT_LIMIT = 65536
MAX_STREAMS = 16


def find_openssl(explicit=None):
    choices = [explicit, shutil.which("openssl"),
               str(Path(sys.prefix) / "Library" / "bin" / "openssl.exe"),
               r"C:\Program Files\Git\usr\bin\openssl.exe"]
    for candidate in choices:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise ValueError("OpenSSL is needed only for keygen on the PC; supply --openssl PATH")


def keygen(destination, openssl=None):
    executable = find_openssl(openssl)
    root = Path(destination).resolve()
    root.mkdir(mode=0o700)  # Refuse to overwrite an existing key directory.
    authority = root / "authority"
    authority.mkdir(mode=0o700)
    config = authority / "openssl.cnf"
    config.write_text("""[req]
distinguished_name = dn
prompt = no
[dn]
CN = NAT4 Tunnel Private CA
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[nas_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:nat4-nas
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
[client_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""", encoding="ascii")

    def run(*args):
        result = subprocess.run([executable] + [str(a) for a in args],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise RuntimeError("OpenSSL failed: " + result.stderr[-1000:])

    run("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3650",
        "-config", config, "-extensions", "ca_ext", "-keyout", authority / "ca-key.pem",
        "-out", authority / "ca.pem")
    secret = secrets.token_hex(32) + "\n"
    for role, name in (("nas", "nat4-nas"), ("client", "nat4-client")):
        folder = root / role
        folder.mkdir(mode=0o700)
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-config", config,
            "-subj", "/CN=" + name, "-keyout", folder / "key.pem", "-out", authority / (role + ".csr"))
        run("x509", "-req", "-in", authority / (role + ".csr"), "-CA", authority / "ca.pem",
            "-CAkey", authority / "ca-key.pem", "-set_serial", "0x" + secrets.token_hex(16),
            "-days", "365", "-sha256", "-extfile", config, "-extensions", role + "_ext",
            "-out", folder / "cert.pem")
        shutil.copyfile(authority / "ca.pem", folder / "ca.pem")
        (folder / "secret.key").write_text(secret, encoding="ascii")
        for private in (folder / "key.pem", folder / "secret.key"):
            private.chmod(0o600)
    (authority / "ca-key.pem").chmod(0o600)
    n.log("[keygen] created {} (certificates valid for 365 days)".format(root))
    n.log("[keygen] copy only nas/ to NAS; keep client/ on PC; do not publish these private keys")
    return root


def credentials(folder, is_server):
    folder = Path(folder)
    secret = bytes.fromhex((folder / "secret.key").read_text(encoding="ascii").strip())
    if len(secret) != 32:
        raise ValueError("secret.key must contain a 32-byte hex key")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if is_server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(folder / "ca.pem"))
    context.load_cert_chain(str(folder / "cert.pem"), str(folder / "key.pem"))
    return secret, context


async def close_writer(writer):
    if writer:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1)
        writer.transport.abort()


class TLSBridge:
    """Let asyncio/OpenSSL own TLS buffering and verification.

    One local socketpair adapts the reliable UDP bytes to asyncio's stock TLS
    implementation. Its other end carries only TLS ciphertext, never plain data.
    """

    def __init__(self, channel):
        self.channel = channel
        self.tasks = []
        self.raw_writer = self.writer = None
        self.error = None

    async def start(self, context, is_server):
        app, wire = socket.socketpair()
        app.setblocking(False)
        wire.setblocking(False)
        try:
            owned_wire, wire = wire, None
            raw_reader, self.raw_writer = await asyncio.open_connection(sock=owned_wire)

            async def outbound():
                while True:
                    data = await raw_reader.read(32768)
                    if not data:
                        return
                    await self.channel.write(data)

            async def inbound():
                while True:
                    data = await self.channel.read()
                    self.raw_writer.write(data)
                    await self.raw_writer.drain()

            async def guarded(function):
                try:
                    await function()
                except asyncio.CancelledError:
                    pass
                except Exception as error:
                    self.error = error
                    self.raw_writer.transport.abort()

            self.tasks = [asyncio.create_task(guarded(fn)) for fn in (outbound, inbound)]
            # These APIs take ownership before TLS negotiation completes. Do
            # not close their raw socket again when certificate checks fail.
            owned_app, app = app, None
            if is_server:
                reader = asyncio.StreamReader(limit=CREDIT_LIMIT)
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await asyncio.get_running_loop().connect_accepted_socket(
                    lambda: protocol, owned_app, ssl=context, ssl_handshake_timeout=15)
                self.reader = reader
                self.writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_running_loop())
            else:
                self.reader, self.writer = await asyncio.open_connection(
                    sock=owned_app, ssl=context, server_hostname="nat4-nas", ssl_handshake_timeout=15,
                    limit=CREDIT_LIMIT)
            return self.reader, self.writer
        except BaseException:
            if app is not None:
                app.close()
            if wire is not None:
                wire.close()
            await self.close()
            raise

    async def close(self):
        # Abort is bounded even when the other endpoint disappeared. The TLS
        # byte stream cannot be resumed after path loss; applications reconnect.
        if self.writer:
            self.writer.transport.abort()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await close_writer(self.raw_writer)
        await close_writer(self.writer)


class Stream:
    def __init__(self, owner, sid, reader=None, writer=None):
        self.owner, self.sid = owner, sid
        self.reader, self.writer = reader, writer
        self.credit = CREDIT_LIMIT
        self.receive_credit = CREDIT_LIMIT
        self.buffer = bytearray()
        self.credit_event = asyncio.Event()
        self.data_event = asyncio.Event()
        self.opened = asyncio.Event()
        self.remote_fin = self.tx_fin = self.rx_fin = self.closed = False
        self.tasks = []

    def start(self):
        self.opened.set()
        self.tasks.extend([asyncio.create_task(self._read_tcp()), asyncio.create_task(self._write_tcp())])

    async def _read_tcp(self):
        try:
            while not self.closed:
                while self.credit == 0:
                    self.credit_event.clear()
                    await self.credit_event.wait()
                data = await self.reader.read(min(BLOCK, self.credit))
                if not data:
                    await self.owner.send(FIN, self.sid)
                    self.tx_fin = True
                    await self._finished()
                    return
                self.credit -= len(data)
                await self.owner.send(DATA, self.sid, data)
        except asyncio.CancelledError:
            pass
        except Exception:
            await self.reset()

    async def _write_tcp(self):
        try:
            while not self.closed:
                self.data_event.clear()
                if self.buffer:
                    data = bytes(self.buffer)
                    self.buffer.clear()
                    self.writer.write(data)
                    await self.writer.drain()
                    self.receive_credit += len(data)
                    await self.owner.send(CREDIT, self.sid, struct.pack("!I", len(data)))
                elif self.remote_fin:
                    self.writer.write_eof()
                    await self.writer.drain()
                    self.rx_fin = True
                    await self._finished()
                    return
                else:
                    await self.data_event.wait()
        except asyncio.CancelledError:
            pass
        except Exception:
            await self.reset()

    async def _finished(self):
        if self.tx_fin and self.rx_fin:
            await self.close()

    async def reset(self):
        if not self.closed:
            with contextlib.suppress(Exception):
                await self.owner.send(RESET, self.sid)
            await self.close(abort=True)

    async def close(self, abort=False):
        if self.closed:
            return
        self.closed = True
        self.owner.streams.pop(self.sid, None)
        own_task = asyncio.current_task()
        others = [t for t in self.tasks if t is not own_task]
        for task in others:
            task.cancel()
        await asyncio.gather(*others, return_exceptions=True)
        if self.writer:
            if abort:
                self.writer.transport.abort()
            await close_writer(self.writer)


class Multiplexer:
    def __init__(self, reader, writer, is_server, target=None, listen=("127.0.0.1", 18080)):
        self.reader, self.writer = reader, writer
        self.is_server, self.target, self.listen = is_server, target, listen
        self.streams = {}
        self.next_sid = 1
        self.last_open = 0
        self.outgoing = asyncio.Queue(128)
        self.tasks = []
        self.listener = None
        self.closed = False
        self.ready = asyncio.Event()
        self.error = None

    async def send(self, kind, sid, payload=b""):
        while self.outgoing.full():
            if self.closed or self.error:
                raise ConnectionError("multiplexer closed")
            await asyncio.sleep(0.01)
        if self.closed or self.error:
            raise ConnectionError("multiplexer closed")
        self.outgoing.put_nowait(FRAME.pack(kind, sid, len(payload)) + payload)

    async def _write(self):
        while True:
            data = await self.outgoing.get()
            self.writer.write(data)
            await self.writer.drain()

    async def _accept(self, reader, writer):
        if self.closed or len(self.streams) >= MAX_STREAMS or self.next_sid > 0xFFFFFFFF:
            await close_writer(writer)
            return
        sid = self.next_sid
        self.next_sid += 1
        stream = Stream(self, sid, reader, writer)
        self.streams[sid] = stream
        # Track the callback too, so tunnel shutdown interrupts a pending OPEN.
        stream.tasks.append(asyncio.current_task())
        try:
            await self.send(OPEN, sid)
            await asyncio.wait_for(stream.opened.wait(), 8)
        except asyncio.CancelledError:
            pass
        except Exception:
            await stream.reset()

    async def _open_target(self, stream):
        try:
            stream.reader, stream.writer = await asyncio.wait_for(
                asyncio.open_connection(*self.target, limit=CREDIT_LIMIT), 5)
            await self.send(OPEN_OK, stream.sid)
            stream.start()
        except asyncio.CancelledError:
            pass
        except Exception as error:
            n.log("[tunnel] TARGET_CONNECT_FAILED {}: {}".format(n.addr_text(self.target), error))
            await stream.reset()

    async def _read(self):
        while True:
            kind, sid, length = FRAME.unpack(await self.reader.readexactly(FRAME.size))
            if (kind not in range(1, 7) or sid == 0 or length > BLOCK
                    or (kind in (OPEN, OPEN_OK, FIN, RESET) and length != 0)
                    or (kind == CREDIT and length != 4) or (kind == DATA and length == 0)):
                raise ValueError("invalid multiplex frame")
            payload = await self.reader.readexactly(length)
            if kind == OPEN:
                if not self.is_server or sid <= self.last_open:
                    raise ValueError("invalid OPEN direction or reused stream id")
                self.last_open = sid
                if len(self.streams) >= MAX_STREAMS:
                    await self.send(RESET, sid)
                    continue
                stream = Stream(self, sid)
                self.streams[sid] = stream
                stream.tasks.append(asyncio.create_task(self._open_target(stream)))
                continue
            stream = self.streams.get(sid)
            if stream is None:
                continue  # In-flight CREDIT/FIN can cross a stream RESET.
            if kind == RESET:
                await stream.close(abort=True)
            elif kind == OPEN_OK:
                if self.is_server or stream.opened.is_set():
                    raise ValueError("unexpected OPEN_OK")
                stream.start()
            elif kind == DATA:
                if not stream.opened.is_set() or stream.remote_fin or length > stream.receive_credit:
                    raise ValueError("peer exceeded stream receive credit")
                stream.receive_credit -= length
                stream.buffer.extend(payload)
                stream.data_event.set()
            elif kind == FIN:
                if not stream.opened.is_set() or stream.remote_fin:
                    raise ValueError("unexpected FIN")
                stream.remote_fin = True
                stream.data_event.set()
            elif kind == CREDIT:
                amount = struct.unpack("!I", payload)[0]
                if amount == 0 or stream.credit + amount > CREDIT_LIMIT:
                    raise ValueError("invalid stream credit")
                stream.credit += amount
                stream.credit_event.set()

    async def run(self):
        try:
            self.writer.write(b"N4MUX1")
            await self.writer.drain()
            if await asyncio.wait_for(self.reader.readexactly(6), 10) != b"N4MUX1":
                raise ValueError("incompatible tunnel version")
            self.tasks = [asyncio.create_task(self._read()), asyncio.create_task(self._write())]
            if self.is_server:
                n.log("[tunnel] TUNNEL_READY target={} mutual_TLS=true".format(n.addr_text(self.target)))
            else:
                self.listener = await asyncio.start_server(self._accept, *self.listen, limit=CREDIT_LIMIT)
                self.listen = self.listener.sockets[0].getsockname()
                n.log("[tunnel] TUNNEL_READY listen={} mutual_TLS=true".format(n.addr_text(self.listen)))
            self.ready.set()
            finished, _ = await asyncio.wait(self.tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                await task
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.error = error
            raise
        finally:
            await self.close()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.listener:
            self.listener.close()
            await self.listener.wait_closed()
        for stream in list(self.streams.values()):
            await stream.close(abort=True)
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


async def run_tunnel(endpoint, remote, session, own_id, other_id, is_server, secret, context,
                     target=None, listen=("127.0.0.1", 18080), on_ready=None, **transport_options):
    channel = await rudp.attach(endpoint, remote, session, own_id, other_id, secret, is_server,
                                **transport_options)
    bridge = TLSBridge(channel)
    mux = None
    task = None
    try:
        await channel.wait_ready()
        reader, writer = await bridge.start(context, is_server)
        mux = Multiplexer(reader, writer, is_server, target, listen)
        task = asyncio.create_task(mux.run())
        if on_ready:
            # Test/deployment integration hook; never exposes private key bytes.
            while not mux.ready.is_set() and not task.done():
                await asyncio.sleep(0.01)
            if mux.ready.is_set():
                on_ready(mux)
        await task
    finally:
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if mux:
            await mux.close()
        await bridge.close()
        await channel.close()
        n.log("[tunnel] closed sent_bytes={} received_bytes={} retransmissions={}".format(
            channel.sent_bytes, channel.received_bytes, channel.retransmissions))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("keygen", help="create a private CA and separate NAS/PC credentials")
    keys.add_argument("--out", default="tunnel-keys")
    keys.add_argument("--openssl", help="path to openssl executable (needed only on the key-generation PC)")
    for role in ("serve", "connect"):
        command = commands.add_parser(role)
        command.add_argument("--server", required=True)
        command.add_argument("--room", default="webdav-1")
        command.add_argument("--id", default="alice" if role == "serve" else "bob")
        command.add_argument("--keys", required=True, help="nas/ or client/ credentials from keygen")
        command.add_argument("--strategy", choices=("predict", "fanout"), default="predict")
        command.add_argument("--fanout", type=int, default=32)
        command.add_argument("--pps", type=int, default=200)
        command.add_argument("--port-min", type=int, default=1024)
        command.add_argument("--port-max", type=int, default=65535)
        command.add_argument("--probes")
        command.add_argument("--rate-kib", type=int, default=512, help="per-direction payload rate cap, KiB/s")
        if role == "serve":
            command.add_argument("--target", default="127.0.0.1:5005", help="fixed TCP service on NAS")
        else:
            command.add_argument("--listen", default="127.0.0.1:18080", help="local loopback TCP listener")
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            keygen(args.out, args.openssl)
            return 0
        is_server = args.command == "serve"
        secret, context = credentials(args.keys, is_server)
        target = n.address(args.target) if is_server else None
        listen = n.address(args.listen, allow_zero=True) if not is_server else None
        if listen and not ipaddress.IPv4Address(listen[0]).is_loopback:
            raise ValueError("--listen must be a loopback address, e.g. 127.0.0.1:18080")
        if not 16 <= args.rate_kib <= 10240:
            raise ValueError("--rate-kib must be 16..10240")
        cfg = n.PeerConfig(n.address(args.server), args.room, args.id, args.strategy,
                           args.fanout, args.pps, args.port_min, args.port_max, secrets.randbits(64),
                           [n.address(p) for p in args.probes.split(",")] if args.probes else None)

        def connected(endpoint, remote, session, other):
            n.log("[tunnel] direct path verified; starting peer authentication and TLS")
            asyncio.run(run_tunnel(endpoint, remote, session, args.id, other, is_server,
                                   secret, context, target, listen, rate=args.rate_kib * 1024))

        result = n.run_peer(cfg, on_connected=connected)
        return 0 if result.connected else 2
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, asyncio.IncompleteReadError) as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
