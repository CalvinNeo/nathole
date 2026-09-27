#!/usr/bin/env python3
"""Supervise independent TCP tunnels with retries and a local JSON control pipe."""

import argparse
import json
import math
import os
from pathlib import Path
import queue
import random
import signal
import subprocess
import sys
import threading
import time

import nat4_demo as n
import nat4_tunnel as tunnel


MAX_PEERS = 32


def address(value, allow_zero=False):
    if not isinstance(value, str):
        raise ValueError("endpoints must be IPv4:port strings")
    return n.address(value, allow_zero=allow_zero)


def load_config(filename):
    path = Path(filename).resolve()
    with path.open(encoding="utf-8") as handle:
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("service configuration is too large")
    value = json.loads(raw)
    if (not isinstance(value, dict) or type(value.get("version", 1)) is not int
            or value.get("version", 1) != 1):
        raise ValueError("service configuration must be a version 1 object")
    retry = value.get("retry", {})
    if not isinstance(retry, dict):
        raise ValueError("retry must be an object")
    delays = []
    for key, default in (("initial_seconds", 1), ("max_seconds", 30)):
        delay = retry.get(key, default)
        if (isinstance(delay, bool) or not isinstance(delay, (int, float))
                or not 0.1 <= delay <= 300 or not math.isfinite(delay)):
            raise ValueError("retry.%s must be a number from 0.1 to 300" % key)
        delays.append(float(delay))
    if delays[1] < delays[0]:
        raise ValueError("retry.max_seconds must be at least initial_seconds")
    peers = value.get("peers", [])
    if not isinstance(peers, list) or len(peers) > MAX_PEERS:
        raise ValueError("peers must be an array of at most %d entries" % MAX_PEERS)
    specs = {}
    for peer in peers:
        if not isinstance(peer, dict):
            raise ValueError("each peer must be an object")
        name = peer.get("name")
        if not isinstance(name, str) or not n.valid_label(name) or name in specs:
            raise ValueError("peer names must be unique labels")
        role = peer.get("role", "serve")
        if role not in ("serve", "connect"):
            raise ValueError("peer role must be serve or connect")
        server = n.addr_text(address(peer.get("server", "")))
        room = peer.get("room", name)
        own_id = peer.get("id", "nas" if role == "serve" else "client")
        if (not isinstance(room, str) or not n.valid_label(room)
                or not isinstance(own_id, str) or not n.valid_label(own_id) or len(own_id) > 32):
            raise ValueError("invalid peer room or id")
        key_path = peer.get("keys")
        if not isinstance(key_path, str) or not key_path:
            raise ValueError("peer keys must be a credential directory")
        keys = Path(key_path).expanduser()
        if not keys.is_absolute():
            keys = path.parent / keys
        keys = keys.resolve()
        tunnel.credentials(keys, role == "serve")
        endpoint_key = "target" if role == "serve" else "listen"
        endpoint = address(peer.get(endpoint_key, "127.0.0.1:0"), allow_zero=role == "connect")
        if role == "connect" and not tunnel.ipaddress.IPv4Address(endpoint[0]).is_loopback:
            raise ValueError("connect listeners must use a loopback address")
        strategy = peer.get("strategy", "predict")
        if strategy not in ("predict", "fanout"):
            raise ValueError("invalid peer strategy")
        options = {}
        for key, default, low, high in (("fanout", 32, 1, 512), ("pps", 200, 1, 2000),
                                        ("rate_kib", 512, 16, 10240),
                                        ("port_min", 1024, 1, 65532), ("port_max", 65535, 4, 65535)):
            item = peer.get(key, default)
            if isinstance(item, bool) or not isinstance(item, int) or not low <= item <= high:
                raise ValueError("invalid peer %s" % key)
            options[key] = item
        if options["port_max"] - options["port_min"] < 3:
            raise ValueError("peer port range is too small")
        argv = [role, "--events-json", "--server", server, "--room", room,
                "--id", own_id, "--keys", str(keys), "--" + endpoint_key, n.addr_text(endpoint),
                "--strategy", strategy]
        for key, item in options.items():
            argv.extend(["--" + key.replace("_", "-"), str(item)])
        if peer.get("probes") is not None:
            probes = peer["probes"]
            if not isinstance(probes, list) or len(probes) != 3:
                raise ValueError("probes must contain three IPv4 endpoints")
            parsed = [n.addr_text(address(item)) for item in probes]
            if len(set(parsed)) != 3:
                raise ValueError("probes must be distinct")
            argv.extend(["--probes", ",".join(parsed)])
        specs[name] = argv
    return specs, delays


class Worker:
    def __init__(self, name, argv, initial):
        self.name, self.argv = name, argv
        self.process = None
        self.reader = None
        self.ready = False
        self.endpoint = None
        self.next_start = 0.0
        self.delay = initial
        self.started_at = 0.0

    def close(self):
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        if self.reader:
            self.reader.join(timeout=1)
        process.stdout.close()
        self.process = None
        self.ready = False
        self.endpoint = None


class Service:
    def __init__(self, filename, control_stdio=False):
        self.filename = str(Path(filename).resolve())
        self.control_stdio = control_stdio
        self.workers = {}
        self.initial, self.maximum = 1.0, 30.0
        self.events = queue.Queue(256)
        self.stop = threading.Event()

    def emit(self, event, **fields):
        try:
            print(json.dumps(dict(version=1, event=event, **fields), separators=(",", ":")), flush=True)
        except (BrokenPipeError, OSError):
            self.stop.set()

    def reload(self):
        specs, delays = load_config(self.filename)
        # Validate the complete replacement before interrupting any live tunnel.
        self.initial, self.maximum = delays
        for name in list(self.workers):
            worker = self.workers[name]
            if specs.get(name) != worker.argv:
                worker.close()
                del self.workers[name]
                self.emit("peer_removed", name=name)
        for name, argv in specs.items():
            if name not in self.workers:
                self.workers[name] = Worker(name, argv, self.initial)

    def _read_control(self):
        while not self.stop.is_set():
            line = sys.stdin.readline(65537)
            if not line:
                self.stop.set()
                return
            try:
                value = json.loads(line) if len(line) <= 65536 else None
                if not isinstance(value, dict):
                    raise ValueError("expected a JSON object")
            except ValueError:
                value = {"command": "invalid"}
            try:
                self.events.put(("control", value), timeout=1)
            except queue.Full:
                self.stop.set()

    def _read_worker(self, worker, process):
        for line in process.stdout:
            try:
                value = json.loads(line)
                if not isinstance(value, dict) or value.get("version") != 1:
                    continue
                if value.get("event") != "ready":
                    continue
                self.events.put(("ready", worker, process, value), timeout=1)
            except (ValueError, queue.Full):
                continue

    def _start(self, worker):
        script = str(Path(__file__).resolve().with_name("nat4_tunnel.py"))
        process = subprocess.Popen([sys.executable, "-B", "-u", script] + worker.argv,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace", bufsize=1,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        worker.process = process
        worker.started_at = time.monotonic()
        worker.reader = threading.Thread(target=self._read_worker, args=(worker, process), daemon=True)
        worker.reader.start()
        self.emit("peer_starting", name=worker.name, pid=process.pid)

    def _retry(self, worker, exit_code):
        if worker.ready and time.monotonic() - worker.started_at >= 30:
            worker.delay = self.initial
        worker.close()
        delay = min(self.maximum, worker.delay * random.uniform(0.8, 1.2))
        worker.next_start = time.monotonic() + delay
        worker.delay = min(self.maximum, worker.delay * 2)
        self.emit("peer_retry", name=worker.name, exit_code=exit_code, retry_seconds=round(delay, 3))

    def _control(self, value):
        command, request_id = value.get("command"), value.get("id")
        if not isinstance(request_id, (str, int, type(None))) or isinstance(request_id, bool):
            request_id = None
        try:
            if command == "reload":
                self.reload()
                self.emit("reloaded", id=request_id)
            elif command == "status":
                peers = [{"name": w.name, "ready": w.ready, "endpoint": w.endpoint,
                          "pid": w.process.pid if w.process else None} for w in self.workers.values()]
                self.emit("status", id=request_id, peers=peers)
            elif command == "stop":
                self.stop.set()
            else:
                raise ValueError("command must be reload, status, or stop")
        except (OSError, ValueError, TypeError, KeyError) as error:
            # Do not echo configuration or credential contents into the protocol.
            self.emit("command_failed", id=request_id, error=type(error).__name__)

    def run(self):
        try:
            self.reload()
            if self.control_stdio:
                threading.Thread(target=self._read_control, daemon=True).start()
            self.emit("started", pid=os.getpid())
            while not self.stop.is_set():
                for worker in list(self.workers.values()):
                    if worker.process is not None:
                        code = worker.process.poll()
                        if code is not None:
                            self._retry(worker, code)
                    elif time.monotonic() >= worker.next_start:
                        try:
                            self._start(worker)
                        except OSError:
                            self._retry(worker, None)
                try:
                    event = self.events.get(timeout=0.1)
                except queue.Empty:
                    continue
                if event[0] == "control":
                    self._control(event[1])
                else:
                    _, worker, process, value = event
                    if self.workers.get(worker.name) is worker and worker.process is process:
                        worker.ready = True
                        worker.endpoint = value.get("listen") or value.get("target")
                        self.emit("peer_ready", name=worker.name, endpoint=worker.endpoint)
            return 0
        finally:
            self.stop.set()
            for worker in self.workers.values():
                worker.close()
            self.emit("stopped")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="version 1 service JSON configuration")
    parser.add_argument("--control-stdio", action="store_true", help="read JSON commands; stop on stdin EOF")
    args = parser.parse_args(argv)
    service = Service(args.config, args.control_stdio)
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, lambda *_: service.stop.set())
    try:
        return service.run()
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("Service configuration failed: %s" % type(error).__name__, file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
