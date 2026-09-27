# Persistent tunnel service

`nat4_tunnel.py daemon` runs independently of any application. It supervises one
`serve` or `connect` worker per configured peer, waits for peers across coordinator
timeouts, and restarts failed workers with bounded exponential backoff and jitter.
Existing `keygen`, `serve`, and `connect` commands retain their behavior.

Keep `nat4_service.py` alongside the three existing Python modules. Python 3.8+
and the standard library are sufficient at runtime. Credential generation still
requires OpenSSL on the machine running `keygen`.

```json
{
  "version": 1,
  "retry": {"initial_seconds": 1, "max_seconds": 30},
  "peers": [{
    "name": "laptop",
    "role": "serve",
    "server": "203.0.113.10:40000",
    "room": "my-private-pair",
    "id": "nas",
    "keys": "./tunnel-keys/nas",
    "target": "127.0.0.1:5005"
  }]
}
```

Run `python -u nat4_tunnel.py daemon --config service.json`. Relative credential
paths resolve against the configuration file. Use a distinct room and credential
bundle for each device. A client peer uses `role: "connect"`, `id: "client"`, its
client credentials, and `listen: "127.0.0.1:0"` (an automatically assigned port).
At most 32 peers are allowed. `strategy`, `fanout`, `pps`, `rate_kib`, `port_min`,
`port_max`, and a three-element `probes` array are optional per-peer settings.

## Embedding in an application

Launch the daemon as a child process with `--control-stdio`, piping stdin and
stdout. Stderr contains human-readable tunnel logs. Stdout contains JSON lines
with `version: 1` and an `event` field:

- `started`: configuration validated and supervision started.
- `peer_starting`: worker `name` and `pid`.
- `peer_ready`: authenticated tunnel `name` and TCP `endpoint`.
- `peer_retry`: worker `name`, `exit_code`, and `retry_seconds`.
- `peer_removed`, `reloaded`, `status`, `command_failed`, `stopped`.

Send one JSON object per line on stdin:

```json
{"id":"update-1","command":"reload"}
{"id":"check-1","command":"status"}
{"command":"stop"}
```

Replace the configuration file atomically before `reload`. The complete new
configuration and credentials are validated before changing workers. Unchanged
peers keep their live connections; removed or changed peers are stopped and
reaped. Invalid updates return `command_failed` without disrupting current peers.
`status` includes readiness, PID, and endpoint for each peer. An empty peer array
is valid, allowing an application to enroll its first device later. Request IDs
are echoed in replies. Credential bytes are never included in events.

Closing stdin stops the daemon and all its workers, including when the parent
process exits. SIGINT/SIGTERM also stop supervision. On Windows, use the stop
command or EOF for graceful shutdown; forcibly terminating the daemon bypasses
Python cleanup. Applications should keep ownership of the stdin pipe and close
it before resorting to process termination.

Reconnection creates a new tunnel. Interrupted TCP streams and application file
transfers are not resumed or replayed. A `connect` listener using port 0 may receive
a new port after reconnecting; use the new `peer_ready` endpoint. This service
does not add relay fallback, remote enrollment, or an unauthenticated network
administration port. The embedding application owns enrollment authorization and
credential storage.

Run `python -B -m unittest -v test_nat4_service test_nat4_tunnel` for service and
tunnel coverage, including real-process reload, retries, EOF shutdown, and data
forwarding.
