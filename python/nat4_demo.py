#!/usr/bin/env python3
"""NAT4 UDP punching experiment. Python 3.8+, standard library only.

Wire-compatible with the Rust demo in this repository. Run --help or read
README.md before a real-network experiment. This is not a VPN or a relay.
"""

import argparse
import errno
import ipaddress
import secrets
import selectors
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Tuple

Address = Tuple[str, int]
MASK64 = (1 << 64) - 1
CASES = ("predict", "random-small", "random-full", "predict-on-random")
_print_lock = threading.Lock()


def log(message):
    with _print_lock:
        print(message, flush=True)


def valid_label(value):
    return 0 < len(value) <= 96 and all(
        c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for c in value
    )


def address(value, allow_zero=False):
    """Literal IPv4 only; no implicit DNS or IPv6 behavior."""
    host, port = value.rsplit(":", 1)
    host, port = str(ipaddress.IPv4Address(host)), int(port)
    if not (0 if allow_zero else 1) <= port <= 65535:
        raise ValueError("port out of range")
    return host, port


def addr_text(value):
    return "{}:{}".format(*value)


def transient(error):
    return isinstance(error, (BlockingIOError, InterruptedError, socket.timeout)) or (
        error.errno in (errno.ECONNRESET, errno.ECONNREFUSED)
        or getattr(error, "winerror", None) in (10054, 10061)
    )


def udp_send(sock, data, target):
    try:
        sock.sendto(data, target)
        return True
    except OSError as error:
        if not transient(error):
            raise
        return False


def udp_recv(sock):
    try:
        data, source = sock.recvfrom(2049)
        return (data, source) if len(data) <= 2048 else None
    except OSError as error:
        if not transient(error):
            raise
        return None


def udp_bind(bind):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(bind)
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


class Rng:
    """Same deterministic port sampler as Rust; never used for session tokens."""

    def __init__(self, seed):
        self.state = max(seed & MASK64, 1)

    def port(self, low, high):
        x = self.state
        x = (x ^ (x << 13)) & MASK64
        x ^= x >> 7
        x = (x ^ (x << 17)) & MASK64
        self.state = x
        return low + x % (high - low + 1)


class Managed:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Control(Managed):
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def send(self, line):
        self.sock.settimeout(5)
        self.sock.sendall((line + "\n").encode("ascii"))

    def recv(self):
        deadline = time.monotonic() + 60
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if len(self.buffer) >= 4096 or remaining <= 0:
                raise ValueError("control line too long or timed out")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4097 - len(self.buffer))
            if not chunk:
                raise ConnectionError("coordinator closed the connection")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        if len(line) + 1 > 4096:
            raise ValueError("control line too long")
        return line.decode("ascii").strip()

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def unpack(data, prefix):
    try:
        header, body = data.split(b"\n", 1)
        kind, dest = header.decode("ascii").split(" ", 1)
        if kind == prefix and len(body) <= 1500:
            return address(dest), body
    except (ValueError, UnicodeError):
        pass
    return None


class Endpoint(Managed):
    """Transport adapter. Peers cannot read the lab NAT mapping table."""

    def __init__(self, gateway=None):
        self.gateway = gateway
        self.sock = udp_bind(("127.0.0.1" if gateway else "0.0.0.0", 0))

    def send(self, text, target):
        self.send_bytes(text.encode("ascii"), target)

    def send_bytes(self, data, target):
        if self.gateway:
            data = ("TO " + addr_text(target) + "\n").encode("ascii") + data
        udp_send(self.sock, data, self.gateway or target)

    def recv(self):
        item = self.recv_bytes()
        if item is None:
            return None
        data, source = item
        try:
            return data.decode("ascii"), source
        except UnicodeError:
            return None

    def recv_bytes(self):
        item = udp_recv(self.sock)
        if item is None:
            return None
        data, source = item
        if self.gateway:
            if source != self.gateway:
                return None
            item = unpack(data, "FROM")
            if item is None:
                return None
            source, data = item
        return data, source

    def close(self):
        self.sock.close()


def probe(endpoint, server):
    nonce = secrets.token_hex(16)
    request = "N4 WHO " + nonce
    prefix = "N4 SEEN " + nonce + " "
    deadline, next_send = time.monotonic() + 3, 0.0
    with selectors.DefaultSelector() as selector:
        selector.register(endpoint.sock, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                endpoint.send(request, server)
                next_send = now + 0.2
            selector.select(max(0, min(next_send, deadline) - time.monotonic()))
            item = endpoint.recv()
            if item:
                text, source = item
                if source == server and text.startswith(prefix):
                    return address(text[len(prefix):])
    raise TimeoutError("UDP probe timed out at {}; check UDP ports/firewall".format(addr_text(server)))


@dataclass
class Packet:
    kind: str
    session: str
    room: str
    sender: str
    round: int
    nonce: str
    seq: int
    body: str

    def encode(self):
        return "N4 {} {} {} {} {} {} {} {}".format(
            self.kind, self.session, self.room, self.sender,
            self.round, self.nonce, self.seq, self.body,
        )

    @classmethod
    def decode(cls, text):
        f = text.split()
        if (len(f) != 9 or f[0] != "N4"
                or f[1] not in ("PUNCH", "ACK", "PING", "PONG")
                or not all(valid_label(f[i]) for i in (2, 3, 4, 6, 8))):
            return None
        try:
            r, seq = int(f[5]), int(f[7])
            if 0 <= r <= MASK64 and 0 <= seq <= 0xFFFFFFFF:
                return cls(f[1], f[2], f[3], f[4], r, f[6], seq, f[8])
        except ValueError:
            pass
        return None


@dataclass
class ServerConfig:
    rounds: int = 12
    round_ms: int = 1500
    gap_ms: int = 500


class Server(Managed):
    """TCP rendezvous and three UDP address observers. No data forwarding."""

    def __init__(self, bind=("0.0.0.0", 40000), config=None):
        self.config = config or ServerConfig()
        cfg = self.config
        if (not 0 <= bind[1] <= 65533 or not 1 <= cfg.rounds <= 1000
                or not 200 <= cfg.round_ms <= 30000 or not 0 <= cfg.gap_ms <= 10000):
            raise ValueError("invalid server address / rounds / timing")
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.pending = {}
        self.controls = set()
        self.workers = []
        self.error = None
        self.probe_replies = 0
        self.sockets = []
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sockets.append(listener)
            listener.bind(bind)
            listener.listen(64)
            listener.setblocking(False)
            self.address = listener.getsockname()
            for offset in range(3):
                self.sockets.append(udp_bind((bind[0], bind[1] + offset if bind[1] else 0)))
            self.probes = [s.getsockname() for s in self.sockets[1:]]
        except BaseException:
            for sock in self.sockets:
                sock.close()
            raise
        self.thread = threading.Thread(target=self._loop, name="coordinator", daemon=True)
        self.thread.start()

    def _loop(self):
        try:
            with selectors.DefaultSelector() as selector:
                for sock in self.sockets:
                    selector.register(sock, selectors.EVENT_READ)
                while not self.stop.is_set():
                    for key, _ in selector.select(0.05):
                        sock = key.fileobj
                        if sock is self.sockets[0]:
                            client, _ = sock.accept()
                            control = Control(client)
                            with self.lock:
                                admitted = len(self.controls) < 128
                                if admitted:
                                    self.controls.add(control)
                            if not admitted:
                                control.close()
                                continue
                            self.workers = [t for t in self.workers if t.is_alive()]
                            worker = threading.Thread(target=self._register, args=(control,), daemon=True)
                            self.workers.append(worker)
                            worker.start()
                        else:
                            for _ in range(64):
                                item = udp_recv(sock)
                                if item is None:
                                    break
                                data, source = item
                                try:
                                    f = data.decode("ascii").split()
                                except UnicodeError:
                                    continue
                                if len(f) == 3 and f[:2] == ["N4", "WHO"] and valid_label(f[2]):
                                    reply = "N4 SEEN {} {}".format(f[2], addr_text(source))
                                    if udp_send(sock, reply.encode("ascii"), source):
                                        self.probe_replies += 1
                    with self.lock:
                        expired = [room for room, (_, _, since) in self.pending.items()
                                   if time.monotonic() - since >= 55]
                        old = [self.pending.pop(room)[1] for room in expired]
                    for control in old:
                        self._release(control)
        except Exception as error:
            if not self.stop.is_set():
                self.error = error
                log("[server] fatal: {}".format(error))

    def _release(self, control):
        with self.lock:
            self.controls.discard(control)
        control.close()

    def _register(self, control):
        owned = [control]
        try:
            f = control.recv().split()
            if (len(f) != 3 or f[0] != "JOIN" or not valid_label(f[1])
                    or not valid_label(f[2]) or len(f[2]) > 32):
                raise ValueError("expected JOIN room id (id <= 32 characters)")
            room, peer_id = f[1:]
            with self.lock:
                first = self.pending.pop(room, None)
                if first is None:
                    if len(self.pending) >= 64:
                        raise ValueError("too many pending rooms")
                    control.send("WAIT")
                    self.pending[room] = (peer_id, control, time.monotonic())
                    owned.clear()  # Ownership transfers to the pending room.
                    return
            first_id, first_control, _ = first
            owned.append(first_control)
            if first_id == peer_id:
                for peer in owned:
                    peer.send("ERROR duplicate-peer-id")
                return
            self._session(first_control, control, first_id, peer_id)
        except (OSError, ValueError) as error:
            if not self.stop.is_set():
                log("[server] session error: {}".format(error))
                for peer in owned:
                    try:
                        peer.send("ERROR session-failed")
                    except OSError:
                        pass
        except Exception as error:
            self.error = error
        finally:
            for peer in owned:
                self._release(peer)

    @staticmethod
    def _plan(control):
        f = control.recv().split()
        if len(f) != 3 or f[0] != "PLAN":
            raise ValueError("expected PLAN")
        target = address(f[1])
        samples = [address(s) for s in f[2].split(",")]
        if len(samples) != 3 or any(a[0] != target[0] for a in samples):
            raise ValueError("PLAN requires one stable public IPv4 address")
        return target

    @staticmethod
    def _result(control):
        f = control.recv().split()
        if len(f) != 2 or f[0] != "RESULT" or not 0 <= int(f[1]) <= 0xFFFFFFFF:
            raise ValueError("expected RESULT")
        return int(f[1])

    def _session(self, a, b, aid, bid):
        cfg, tag = self.config, secrets.token_hex(16)
        ports = ",".join(str(p[1]) for p in self.probes)
        for control, side, other in ((a, "A", bid), (b, "B", aid)):
            control.send("MATCH {} {} {} {} {} {}".format(
                tag, side, other, cfg.rounds, cfg.round_ms, ports))
        for r in range(cfg.rounds):
            a.send("ROUND {}".format(r))
            b.send("ROUND {}".format(r))
            ap, bp = self._plan(a), self._plan(b)
            a.send("GO " + addr_text(bp))
            b.send("GO " + addr_text(ap))
            ac, bc = self._result(a), self._result(b)
            if ac >= 3 and bc >= 3:
                a.send("DONE OK")
                b.send("DONE OK")
                return
            if r + 1 < cfg.rounds and self.stop.wait(cfg.gap_ms / 1000):
                return
        a.send("DONE MISS")
        b.send("DONE MISS")

    def close(self):
        self.stop.set()
        self.thread.join(2)
        with self.lock:
            active = list(self.controls)
            self.pending.clear()
        for control in active:
            self._release(control)
        for worker in self.workers:
            worker.join(2)
        for sock in self.sockets:
            sock.close()


@dataclass
class PeerConfig:
    server: Address
    room: str
    id: str
    strategy: str = "predict"
    fanout: int = 32
    pps: int = 200
    port_low: int = 1024
    port_high: int = 65535
    seed: int = 1
    probes: Optional[List[Address]] = None
    gateway: Optional[Address] = None


@dataclass
class Attempt:
    round: int = 0
    pongs: int = 0
    remote: Optional[Address] = None
    local: Optional[Address] = None
    mean_rtt_ms: float = 0.0


@dataclass
class PeerResult:
    connected: bool
    attempt: Attempt


def predict(samples):
    if len(samples) != 3 or any(a[0] != samples[0][0] for a in samples):
        raise ValueError("prediction requires three samples on one public IPv4 address")
    p0, p1, p2 = (a[1] for a in samples)
    d1, d2 = p1 - p0, p2 - p1
    if d1 == d2 == 0:
        step, label = 0, "stable-mapping"
    elif d1 == d2 and 0 < abs(d1) <= 64:
        step, label = d2, "sequential-hypothesis"
    else:
        step, label = 1, "irregular-next-port-guess"
    if not 1 <= p2 + step <= 65535:
        raise ValueError("predicted port out of range")
    return (samples[2][0], p2 + step), label


@dataclass
class SocketState:
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    remote: Optional[Address] = None
    seq: int = 0
    pending: Dict[int, float] = field(default_factory=dict)
    pongs: int = 0
    total_rtt: float = 0.0

    def receive(self, text, source, cfg, session, other, r, now):
        """Return a response, or accept one unique echo matching this request.

        The nonce/context checks reject stale/stray packets; they are not a
        cryptographic authentication protocol against an active attacker.
        """
        packet = Packet.decode(text)
        if packet is None or (packet.session, packet.room, packet.sender, packet.round) != (
                session, cfg.room, other, r):
            return None
        if packet.kind == "PUNCH" and packet.body == "probe":
            return replace(packet, kind="ACK", sender=cfg.id).encode()
        if packet.kind == "ACK" and packet.nonce == self.nonce and packet.body == "probe":
            self.remote = source
        elif packet.kind == "PING" and packet.body == "hello-from-" + other:
            return replace(packet, kind="PONG", sender=cfg.id).encode()
        elif (packet.kind == "PONG" and packet.nonce == self.nonce
              and packet.body == "hello-from-" + cfg.id and source == self.remote):
            sent = self.pending.pop(packet.seq, None)
            if sent is not None:
                self.pongs += 1
                self.total_rtt += now - sent
        return None


def punch(cfg, endpoints, target, session, other, r, duration):
    states = [SocketState() for _ in endpoints]
    started = time.monotonic()
    deadline, next_send, cursor = started + duration, started, 0
    with selectors.DefaultSelector() as selector:
        for i, endpoint in enumerate(endpoints):
            selector.register(endpoint.sock, selectors.EVENT_READ, i)
        while time.monotonic() < deadline:
            now = time.monotonic()
            # Some platforms wake selectors at ~16 ms granularity. Preserve the
            # average rate with small batches, but never replay a long backlog.
            next_send = max(next_send, now - 0.02)
            sent_count = 0
            while now >= next_send and sent_count < 32:
                state = states[cursor]
                kind, dest, body = "PUNCH", target, "probe"
                if state.remote:
                    state.seq += 1
                    state.pending = {n: t for n, t in state.pending.items() if now - t < 5}
                    state.pending[state.seq] = now
                    kind, dest, body = "PING", state.remote, "hello-from-" + cfg.id
                endpoints[cursor].send(Packet(kind, session, cfg.room, cfg.id, r,
                                              state.nonce, state.seq, body).encode(), dest)
                cursor = (cursor + 1) % len(endpoints)
                next_send += 1.0 / cfg.pps
                sent_count += 1
            for key, _ in selector.select(max(0, min(next_send, deadline) - time.monotonic())):
                i = key.data
                endpoint, state = endpoints[i], states[i]
                for _ in range(16):
                    item = endpoint.recv()
                    if item is None:
                        break
                    text, source = item
                    before = state.pongs
                    response = state.receive(text, source, cfg, session, other, r, time.monotonic())
                    if response:
                        endpoint.send(response, source)
                    if before < 3 <= state.pongs:
                        log("[{}] VERIFIED round={} local={} remote={} payload=hello-from-{} round_trips=3".format(
                            cfg.id, r + 1, addr_text(endpoint.sock.getsockname()), addr_text(source), cfg.id))
    i = max(range(len(states)), key=lambda j: states[j].pongs)
    best = states[i]
    return Attempt(r + 1, best.pongs, best.remote, endpoints[i].sock.getsockname(),
                   best.total_rtt * 1000 / best.pongs if best.pongs else 0.0)


def run_peer(cfg, on_connected=None):
    if (not valid_label(cfg.room) or not valid_label(cfg.id) or len(cfg.id) > 32
            or cfg.strategy not in ("predict", "fanout") or not 1 <= cfg.fanout <= 512
            or not 1 <= cfg.pps <= 2000 or not 1 <= cfg.port_low <= cfg.port_high - 3
            or cfg.port_high > 65535):
        raise ValueError("invalid peer options")
    with Control(socket.create_connection(cfg.server, timeout=5)) as control, ExitStack() as live_round:
        control.send("JOIN {} {}".format(cfg.room, cfg.id))
        while True:
            matched = control.recv()
            if matched != "WAIT":
                break
            log("[{}] waiting for the second peer in room {}".format(cfg.id, cfg.room))
        f = matched.split()
        if len(f) != 7 or f[0] != "MATCH":
            raise ValueError("coordinator: " + matched)
        session, other, rounds, round_ms = f[1], f[3], int(f[4]), int(f[5])
        if (f[2] not in ("A", "B") or not valid_label(session) or not valid_label(other)
                or not 1 <= rounds <= 1000 or not 200 <= round_ms <= 30000):
            raise ValueError("invalid MATCH parameters")
        probes = cfg.probes or [address("{}:{}".format(cfg.server[0], p)) for p in f[6].split(",")]
        if len(probes) != 3 or len(set(probes)) != 3:
            raise ValueError("provide exactly three distinct IPv4 probe endpoints")
        rng, last, expected_round = Rng(cfg.seed), Attempt(), 0
        while True:
            line = control.recv()
            if line in ("DONE OK", "DONE MISS"):
                connected = line == "DONE OK" and last.pongs >= 3
                log("[{}] {} pongs={} remote={} mean_rtt_ms={:.3f}".format(
                    cfg.id, "DIRECT_OK" if connected else "NO_DIRECT_PATH", last.pongs,
                    addr_text(last.remote) if last.remote else "none", last.mean_rtt_ms))
                if connected and on_connected is not None:
                    chosen = next(e for e in endpoints if e.sock.getsockname() == last.local)
                    control.close()
                    # Keep exactly the socket that proved this path. Binding a
                    # replacement could create a different mapping at the NAT.
                    on_connected(chosen, last.remote, session, other)
                return PeerResult(connected, last)
            if not line.startswith("ROUND "):
                raise ValueError("coordinator: " + line)
            r = int(line[6:])
            if r != expected_round or r >= rounds:
                raise ValueError("unexpected round number")
            expected_round += 1
            live_round.close()
            # Keep this round's sockets alive until DONE/next ROUND, including
            # the entire optional forwarding callback after verified success.
            discovery = live_round.enter_context(Endpoint(cfg.gateway))
            samples = [probe(discovery, server) for server in probes]
            try:
                offered, label = predict(samples)
            except ValueError:
                if cfg.strategy != "fanout" or any(s[0] != samples[0][0] for s in samples):
                    raise
                offered, label = samples[2], "no-valid-next-port-prediction"
            endpoints = [discovery]
            if cfg.strategy == "fanout":
                port = rng.port(cfg.port_low, cfg.port_high)
                while any(s[1] == port for s in samples):
                    port = rng.port(cfg.port_low, cfg.port_high)
                offered = (samples[2][0], port)
                endpoints = [live_round.enter_context(Endpoint(cfg.gateway)) for _ in range(cfg.fanout)]
            sample_text = ",".join(addr_text(s) for s in samples)
            log("[{}] round={} samples=[{}] {} strategy={} advertised={} sockets={}".format(
                cfg.id, r + 1, sample_text, label, cfg.strategy, addr_text(offered), len(endpoints)))
            control.send("PLAN {} {}".format(addr_text(offered), sample_text))
            go = control.recv()
            if not go.startswith("GO "):
                raise ValueError("coordinator: " + go)
            last = punch(cfg, endpoints, address(go[3:]), session, other, r, round_ms / 1000)
            control.send("RESULT {}".format(last.pongs))


@dataclass
class NatConfig:
    public_ip: str
    name: str = "NAT"
    low: int = 20000
    high: int = 21023
    allocation: str = "sequential"
    seed: int = 1
    ttl_ms: int = 1300
    trace: bool = False


@dataclass
class NatStats:
    mappings: int = 0
    outbound: int = 0
    inbound: int = 0
    filtered: int = 0
    expired: int = 0
    capacity_drops: int = 0


@dataclass
class Mapping:
    internal: Address
    remote: Address
    sock: socket.socket
    last_activity: float


class Nat(Managed):
    """Loopback-only APDM + APDF simulator, using real UDP sockets."""

    def __init__(self, config):
        self.config = config
        if (not ipaddress.IPv4Address(config.public_ip).is_loopback
                or not 1 <= config.low <= config.high <= 65535
                or config.allocation not in ("sequential", "random") or config.ttl_ms < 1):
            raise ValueError("invalid loopback NAT configuration")
        self.sock = udp_bind(("127.0.0.1", 0))
        self.gateway = self.sock.getsockname()
        self.stats = NatStats()
        self.error = None
        self.stop = threading.Event()
        self.rng, self.next_port = Rng(config.seed), config.low
        self.thread = threading.Thread(target=self._loop, name=config.name, daemon=True)
        self.thread.start()

    def _allocate(self, internal, remote, mappings):
        cfg = self.config
        size = cfg.high - cfg.low + 1
        occupied = {m.sock.getsockname()[1] for m in mappings.values()}
        if len(occupied) < size:
            for _ in range(size * 4):
                if cfg.allocation == "random":
                    port = self.rng.port(cfg.low, cfg.high)
                else:
                    port = self.next_port
                    self.next_port = cfg.low if port == cfg.high else port + 1
                if port in occupied:
                    continue
                try:
                    sock = udp_bind((cfg.public_ip, port))
                except OSError as error:
                    if error.errno in (errno.EADDRINUSE, errno.EACCES):
                        continue
                    raise
                self.stats.mappings += 1
                if cfg.trace:
                    log("[{}] MAP {} -> {} => {}".format(
                        cfg.name, addr_text(internal), addr_text(remote), addr_text(sock.getsockname())))
                return Mapping(internal, remote, sock, time.monotonic())
        self.stats.capacity_drops += 1
        return None

    def _loop(self):
        mappings = {}
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.sock, selectors.EVENT_READ, None)
                try:
                    while not self.stop.is_set():
                        now = time.monotonic()
                        for key, mapping in list(mappings.items()):
                            if now - mapping.last_activity >= self.config.ttl_ms / 1000:
                                selector.unregister(mapping.sock)
                                mapping.sock.close()
                                del mappings[key]
                                self.stats.expired += 1
                        for key, _ in selector.select(0.02):
                            for _ in range(64):
                                item = udp_recv(key.fileobj)
                                if item is None:
                                    break
                                data, source = item
                                if key.data is None:
                                    decoded = unpack(data, "TO")
                                    if decoded is None or not ipaddress.IPv4Address(source[0]).is_loopback:
                                        continue
                                    remote, body = decoded
                                    if not ipaddress.IPv4Address(remote[0]).is_loopback:
                                        continue
                                    map_key = (source, remote)
                                    mapping = mappings.get(map_key)
                                    if mapping is None:
                                        mapping = self._allocate(source, remote, mappings)
                                        if mapping is None:
                                            continue
                                        mappings[map_key] = mapping
                                        selector.register(mapping.sock, selectors.EVENT_READ, mapping)
                                    mapping.last_activity = time.monotonic()
                                    if udp_send(mapping.sock, body, remote):
                                        self.stats.outbound += 1
                                else:
                                    mapping = key.data
                                    if source != mapping.remote:
                                        self.stats.filtered += 1
                                        continue
                                    mapping.last_activity = time.monotonic()
                                    envelope = ("FROM " + addr_text(source) + "\n").encode("ascii") + data
                                    if udp_send(self.sock, envelope, mapping.internal):
                                        self.stats.inbound += 1
                finally:
                    for mapping in mappings.values():
                        selector.unregister(mapping.sock)
                        mapping.sock.close()
        except Exception as error:
            self.error = error
            log("[{}] fatal: {}".format(self.config.name, error))

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.sock.close()


@dataclass
class LabResult:
    case: str
    expected: bool
    a: PeerResult
    b: PeerResult
    mappings: int
    filtered: int
    capacity_drops: int

    @property
    def passed(self):
        return (self.a.connected == self.expected and self.b.connected == self.expected
                and self.capacity_drops == 0)


def run_lab(case, seed=7, trace=False, round_ms=700):
    settings = {
        "predict": ("sequential", "predict", 20000, 21023, 2, True),
        "random-small": ("random", "fanout", 40000, 40031, 8, True),
        "random-full": ("random", "fanout", 1024, 65535, 2, False),
        "predict-on-random": ("random", "predict", 1024, 65535, 2, False),
    }
    allocation, strategy, low, high, rounds, expected = settings[case]
    if not 200 <= round_ms <= 5000:
        raise ValueError("lab round-ms must be 200..5000")
    # Different loopback IPs per case; neither peer knows either NAT's seed.
    octet = CASES.index(case) + 101
    log("\n[lab] case={} seed={} NAT=APDM+APDF allocation={} pool={}-{}".format(
        case, seed, allocation, low, high))
    if case == "random-small":
        log("[lab] CONTROLLED experiment: peers explicitly know the 32-port pool; not a full-range Internet claim.")
    if not expected:
        log("[lab] expected MISS for this seed/budget, not a proof of impossibility")
    with ExitStack() as stack:
        server = stack.enter_context(Server(("127.0.0.1", 0),
                                            ServerConfig(rounds, round_ms, round_ms + 800)))
        nats = [stack.enter_context(Nat(NatConfig(
            "127.64.{}.{}".format(octet, last), name, low, high, allocation,
            (seed + salt) & MASK64, round_ms + 600, trace)))
            for name, last, salt in (("NAT-A", 2, 901), ("NAT-B", 3, 1901))]
        room = secrets.token_hex(8)
        configs = [PeerConfig(server.address, room, peer_id, strategy, 24, 800,
                              low, high, (seed + salt) & MASK64, gateway=nat.gateway)
                   for peer_id, salt, nat in (("alice", 3109, nats[0]), ("bob", 7207, nats[1]))]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run_peer, cfg) for cfg in configs]
            a, b = [f.result(timeout=60 + rounds * (2 * round_ms + 9800) / 1000) for f in futures]
        for component in [server] + nats:
            if component.error:
                raise RuntimeError("lab worker failed") from component.error
        result = LabResult(case, expected, a, b, sum(n.stats.mappings for n in nats),
                           sum(n.stats.filtered for n in nats), sum(n.stats.capacity_drops for n in nats))
    log("[lab] {} case={} direct={} a_pongs={} b_pongs={} mappings={} filtered={} capacity_drops={} server_data_relay=0".format(
        "PASS" if result.passed else "UNEXPECTED", case, a.connected and b.connected,
        a.attempt.pongs, b.attempt.pongs, result.mappings, result.filtered, result.capacity_drops))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server", help="TCP rendezvous + three UDP address observers")
    server.add_argument("--bind", default="0.0.0.0:40000")
    server.add_argument("--rounds", type=int, default=12)
    server.add_argument("--round-ms", type=int, default=1500)
    server.add_argument("--gap-ms", type=int, default=500)
    peer = commands.add_parser("peer", help="try a direct UDP connection; no relay fallback")
    peer.add_argument("--server", required=True)
    peer.add_argument("--room", required=True)
    peer.add_argument("--id", required=True)
    peer.add_argument("--strategy", choices=("predict", "fanout"), default="predict")
    peer.add_argument("--fanout", type=int, default=32)
    peer.add_argument("--pps", type=int, default=200, help="total initiated packets/sec, across all sockets")
    peer.add_argument("--port-min", type=int, default=1024)
    peer.add_argument("--port-max", type=int, default=65535)
    peer.add_argument("--seed", type=int, help="optional reproducible port-sampling seed")
    peer.add_argument("--probes", help="three distinct literal IPv4:port endpoints, comma separated")
    lab = commands.add_parser("lab", help="local APDM + APDF experiment; no external traffic")
    lab.add_argument("--case", choices=("all",) + CASES, default="all")
    lab.add_argument("--seed", type=int, default=7)
    lab.add_argument("--trace", nargs="?", choices=("true", "false"), const="true", default="false")
    lab.add_argument("--round-ms", type=int, default=700, help="200..5000; increase on a slow NAS")
    args = parser.parse_args(argv)
    try:
        if args.command == "server":
            cfg = ServerConfig(args.rounds, args.round_ms, args.gap_ms)
            with Server(address(args.bind, allow_zero=True), cfg) as instance:
                log("[server] TCP={} UDP={} no data relay".format(
                    addr_text(instance.address), ",".join(addr_text(p) for p in instance.probes)))
                while not instance.stop.wait(0.5):
                    if instance.error:
                        raise RuntimeError("coordinator failed") from instance.error
        elif args.command == "peer":
            cfg = PeerConfig(address(args.server), args.room, args.id, args.strategy,
                             args.fanout, args.pps, args.port_min, args.port_max,
                             args.seed if args.seed is not None else secrets.randbits(64),
                             [address(p) for p in args.probes.split(",")] if args.probes else None)
            return 0 if run_peer(cfg).connected else 2
        else:
            cases = CASES if args.case == "all" else (args.case,)
            results = [run_lab(case, args.seed, args.trace == "true", args.round_ms) for case in cases]
            return 0 if all(r.passed for r in results) else 2
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
