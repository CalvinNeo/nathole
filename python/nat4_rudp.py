"""Bounded reliable byte transport for the NAT4 experiment (not QUIC).

Selective acknowledgements, pacing, adaptive timeout, a small congestion window,
and authenticated keepalives. TLS in nat4_tunnel supplies confidentiality.
Only the already-punched UDP socket is used. Python 3.8+, standard library.
"""

import asyncio
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass

import nat4_demo as n

HEADER = struct.Struct("!4sB16sQQQQ")
MAGIC = b"N4R1"
DATA, ACK, HELLO, HELLO_ACK, PING, PONG = range(6)
CHUNK = 1000
WINDOW = 64
QUEUE = 128


@dataclass
class Pending:
    data: bytes
    sent: float
    timeout: float
    retries: int = 0


class ReliableUDP(asyncio.DatagramProtocol):
    def __init__(self, remote, session, own_id, other_id, secret, is_server,
                 gateway=None, rate=512 * 1024, keepalive=5.0, idle_timeout=30.0,
                 send_hook=None):
        if len(secret) != 32 or rate <= 0 or keepalive <= 0 or idle_timeout <= keepalive:
            raise ValueError("invalid reliable transport options")
        context = ("N4R1|" + session + "|" + "|".join(sorted((own_id, other_id)))).encode("ascii")
        self.tag = hashlib.sha256(context).digest()[:16]
        self.tx_key = hmac.new(secret, context + (b"nas" if is_server else b"client"), "sha256").digest()
        self.rx_key = hmac.new(secret, context + (b"client" if is_server else b"nas"), "sha256").digest()
        self.remote, self.gateway = remote, gateway
        self.rate, self.keepalive, self.idle_timeout = rate, keepalive, idle_timeout
        self.send_hook = send_hook  # Test-only deterministic loss/reorder injection.
        self.transport = None
        self.runner = None
        self.ready = asyncio.Event()
        self.wakeup = asyncio.Event()
        self.error = None
        self.tx_queue = asyncio.Queue(QUEUE)
        self.rx_queue = asyncio.Queue(QUEUE)
        self.pending = {}
        self.reorder = {}
        self.tx_next = self.rx_next = self.peer_ack = 0
        self.packet_no = 0
        self.rx_packet_high = -1
        self.rx_packet_bits = 0
        self.cwnd = 4.0
        self.srtt = None
        self.rttvar = 0.0
        self.rto = 0.3
        self.last_rx = time.monotonic()
        self.last_tx = self.last_rx
        self.tokens = float(CHUNK * 4)
        self.token_time = self.last_rx
        self.retransmissions = self.sent_bytes = self.received_bytes = 0
        self.rejected = 0

    def connection_made(self, transport):
        self.transport = transport
        self.runner = asyncio.create_task(self._run())

    def connection_lost(self, error):
        self.fail(error or ConnectionError("UDP transport closed"))

    def error_received(self, error):
        # A closed candidate port can produce an ICMP error on Windows. Once
        # established, authenticated keepalive timeout detects a broken path.
        if not n.transient(error):
            self.fail(error)

    def fail(self, error):
        if self.error is None:
            self.error = error
            self.wakeup.set()

    def _check(self):
        if self.error is not None:
            raise ConnectionError(str(self.error)) from self.error

    def _send(self, kind, seq=0, data=b""):
        if self.error is not None or self.transport is None:
            return
        mask = sum(1 << (s - self.rx_next) for s in self.reorder if s < self.rx_next + WINDOW)
        header = HEADER.pack(MAGIC, kind, self.tag, self.packet_no, seq, self.rx_next, mask)
        self.packet_no += 1
        body = header + data
        packet = body + hmac.new(self.tx_key, body, "sha256").digest()
        target = self.remote
        if self.gateway:
            packet = ("TO " + n.addr_text(target) + "\n").encode("ascii") + packet
            target = self.gateway
        self.last_tx = time.monotonic()
        if self.send_hook:
            self.send_hook(self.transport.sendto, packet, target)
        else:
            self.transport.sendto(packet, target)

    def _fresh(self, packet_no):
        # A retransmission gets a new packet number but retains its data seq.
        if packet_no > self.rx_packet_high:
            shift = packet_no - self.rx_packet_high
            self.rx_packet_bits = ((self.rx_packet_bits << min(shift, 1024)) | 1) & ((1 << 1024) - 1)
            self.rx_packet_high = packet_no
            return True
        distance = self.rx_packet_high - packet_no
        if distance >= 1024 or self.rx_packet_bits & (1 << distance):
            return False
        self.rx_packet_bits |= 1 << distance
        return True

    def datagram_received(self, packet, source):
        if self.error:
            return
        if self.gateway:
            if source != self.gateway:
                return
            wrapped = n.unpack(packet, "FROM")
            if wrapped is None:
                return
            source, packet = wrapped
        if source != self.remote or not HEADER.size + 32 <= len(packet) <= HEADER.size + CHUNK + 32:
            return
        body, signature = packet[:-32], packet[-32:]
        if not hmac.compare_digest(hmac.new(self.rx_key, body, "sha256").digest(), signature):
            self.rejected += 1
            return
        magic, kind, tag, number, seq, ack, mask = HEADER.unpack(body[:HEADER.size])
        data = body[HEADER.size:]
        if magic != MAGIC or tag != self.tag or kind not in range(6) or not self._fresh(number):
            self.rejected += 1
            return
        if ack > self.tx_next or (kind == DATA and not data) or (kind != DATA and data):
            self.fail(ValueError("invalid authenticated transport frame"))
            return
        self.last_rx = time.monotonic()
        self.peer_ack = max(self.peer_ack, ack)
        newly_acked = []
        for s, pending in self.pending.items():
            if s < ack or (ack <= s < ack + WINDOW and mask & (1 << (s - ack))):
                newly_acked.append(s)
                if pending.retries == 0:
                    sample = max(0.001, self.last_rx - pending.sent)
                    if self.srtt is None:
                        self.srtt, self.rttvar = sample, sample / 2
                    else:
                        self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                        self.srtt = 0.875 * self.srtt + 0.125 * sample
                    self.rto = min(2.0, max(0.1, self.srtt + 4 * self.rttvar))
        for s in newly_acked:
            del self.pending[s]
            self.cwnd = min(float(WINDOW), self.cwnd + 1 / self.cwnd)
        if kind == HELLO:
            self._send(HELLO_ACK)
        elif kind == HELLO_ACK:
            self.ready.set()
        elif kind == PING:
            self._send(PONG)
        elif kind == DATA:
            if self.rx_next <= seq < self.rx_next + WINDOW:
                self.reorder.setdefault(seq, data)
                self._flush_received()
            self._send(ACK)
        self.wakeup.set()

    def _flush_received(self):
        while self.rx_next in self.reorder and not self.rx_queue.full():
            chunk = self.reorder.pop(self.rx_next)
            self.rx_queue.put_nowait(chunk)
            self.received_bytes += len(chunk)
            self.rx_next += 1

    async def wait_ready(self, timeout=12):
        deadline = time.monotonic() + timeout
        while not self.ready.is_set():
            self._check()
            if time.monotonic() >= deadline:
                raise TimeoutError("peer authentication timed out; check both key directories and tunnel roles")
            await asyncio.sleep(0.03)

    async def write(self, data):
        # A single writer preserves byte-stream order; TLS bridge owns it.
        for offset in range(0, len(data), CHUNK):
            while self.tx_queue.full():
                self._check()
                await asyncio.sleep(0.01)
            self._check()
            self.tx_queue.put_nowait(data[offset:offset + CHUNK])
            self.wakeup.set()

    async def read(self):
        while True:
            self._check()
            try:
                data = await asyncio.wait_for(self.rx_queue.get(), 0.2)
                before = self.rx_next
                self._flush_received()
                if self.rx_next != before:
                    self._send(ACK)
                return data
            except asyncio.TimeoutError:
                pass

    async def _run(self):
        try:
            hello_at = 0.0
            while self.error is None:
                self.wakeup.clear()
                now = time.monotonic()
                self.tokens = min(CHUNK * 8.0, self.tokens + (now - self.token_time) * self.rate)
                self.token_time = now
                if now - self.last_rx > self.idle_timeout:
                    raise TimeoutError("direct UDP path lost (no authenticated packets); restart both tunnel peers")
                if not self.ready.is_set():
                    if now >= hello_at:
                        self._send(HELLO)
                        hello_at = now + 0.3
                else:
                    reduced = False
                    for seq, pending in list(self.pending.items()):
                        if now - pending.sent >= pending.timeout and self.tokens >= len(pending.data):
                            if pending.retries >= 10:
                                raise TimeoutError("UDP retransmission budget exhausted")
                            if not reduced:
                                self.cwnd = max(2.0, self.cwnd / 2)
                                reduced = True
                            pending.retries += 1
                            pending.timeout = min(3.0, pending.timeout * 2)
                            pending.sent = now
                            self._send(DATA, seq, pending.data)
                            self.tokens -= len(pending.data)
                            self.retransmissions += 1
                    while (not self.tx_queue.empty() and len(self.pending) < int(self.cwnd)
                           and self.tx_next < self.peer_ack + WINDOW and self.tokens >= CHUNK):
                        data = self.tx_queue.get_nowait()
                        self.pending[self.tx_next] = Pending(data, now, self.rto)
                        self._send(DATA, self.tx_next, data)
                        self.tx_next += 1
                        self.sent_bytes += len(data)
                        self.tokens -= len(data)
                    if now - self.last_tx >= self.keepalive:
                        self._send(PING)
                try:
                    await asyncio.wait_for(self.wakeup.wait(), 0.01)
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass
        except Exception as error:
            self.fail(error)

    async def close(self):
        self.fail(ConnectionError("tunnel closed"))
        if self.runner:
            self.runner.cancel()
            await asyncio.gather(self.runner, return_exceptions=True)
        if self.transport:
            self.transport.close()


async def attach(endpoint, remote, session, own_id, other_id, secret, is_server, **options):
    protocol = ReliableUDP(remote, session, own_id, other_id, secret, is_server,
                           gateway=endpoint.gateway, **options)
    # The asyncio transport takes ownership of the ORIGINAL punched socket.
    await asyncio.get_running_loop().create_datagram_endpoint(lambda: protocol, sock=endpoint.sock)
    return protocol
