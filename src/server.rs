use crate::wire::{temporary, Control, MAX_PACKET};
use crate::Result;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub struct ServerConfig {
    pub rounds: usize,
    pub round_ms: u64,
    pub gap_ms: u64,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            rounds: 12,
            round_ms: 1500,
            gap_ms: 500,
        }
    }
}

struct Pending {
    id: String,
    control: Control,
    since: Instant,
}
pub struct Server {
    pub address: SocketAddr,
    pub probes: Vec<SocketAddr>,
    pub probe_replies: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}
impl Server {
    /// Port zero gives the lab independent ephemeral ports. A fixed port P
    /// listens on TCP P and UDP P, P+1, P+2 for real-network use.
    pub fn start(bind: SocketAddr, config: ServerConfig) -> Result<Self> {
        if !bind.is_ipv4()
            || bind.port() > 65533
            || config.rounds == 0
            || config.rounds > 1000
            || !(200..=30000).contains(&config.round_ms)
            || config.gap_ms > 10000
        {
            return Err("invalid server address / rounds / timing".into());
        }
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let mut sockets = Vec::new();
        for offset in 0..3 {
            let socket = UdpSocket::bind(SocketAddr::new(
                bind.ip(),
                if bind.port() == 0 {
                    0
                } else {
                    bind.port() + offset
                },
            ))?;
            socket.set_nonblocking(true)?;
            sockets.push(socket);
        }
        let probes: Vec<SocketAddr> = sockets
            .iter()
            .map(|s| s.local_addr())
            .collect::<std::io::Result<_>>()?;
        let ports = probes
            .iter()
            .map(|a| a.port().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let stop = Arc::new(AtomicBool::new(false));
        let probe_replies = Arc::new(AtomicU64::new(0));
        let udp_stop = stop.clone();
        let count = probe_replies.clone();
        let udp_worker = thread::spawn(move || {
            let mut buf = [0; MAX_PACKET];
            while !udp_stop.load(Ordering::Relaxed) {
                for socket in &sockets {
                    for _ in 0..64 {
                        match socket.recv_from(&mut buf) {
                            Ok((n, from)) => {
                                let Ok(text) = std::str::from_utf8(&buf[..n]) else {
                                    continue;
                                };
                                let f: Vec<_> = text.split_ascii_whitespace().collect();
                                // No PUNCH/PING/PONG forwarding exists on the server.
                                if f.len() == 3
                                    && f[0] == "N4"
                                    && f[1] == "WHO"
                                    && crate::valid_label(f[2])
                                {
                                    let response = format!("N4 SEEN {} {from}", f[2]);
                                    if socket.send_to(response.as_bytes(), from).is_ok() {
                                        count.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            Err(e) if temporary(&e) => break,
                            Err(_) => break,
                        }
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
        let tcp_stop = stop.clone();
        let pending = Arc::new(Mutex::new(HashMap::<String, Pending>::new()));
        let tcp_worker = thread::spawn(move || {
            while !tcp_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let rooms = pending.clone();
                        let ports = ports.clone();
                        thread::spawn(move || {
                            let registration = || -> Result<()> {
                                let mut control = Control::new(stream)?;
                                let line = control.recv()?;
                                let f: Vec<_> = line.split_ascii_whitespace().collect();
                                if f.len() != 3
                                    || f[0] != "JOIN"
                                    || !crate::valid_label(f[1])
                                    || !crate::valid_label(f[2])
                                {
                                    return Err("expected JOIN room id".into());
                                }
                                let room = f[1].to_owned();
                                let id = f[2].to_owned();
                                let mut rooms = rooms.lock().unwrap();
                                rooms.retain(|_, p| p.since.elapsed() < Duration::from_secs(55));
                                if let Some(mut first) = rooms.remove(&room) {
                                    drop(rooms);
                                    if first.id == id {
                                        first.control.send("ERROR duplicate-peer-id")?;
                                        control.send("ERROR duplicate-peer-id")?;
                                        return Ok(());
                                    }
                                    if let Err(error) = session(
                                        &mut first.control,
                                        &mut control,
                                        &first.id,
                                        &id,
                                        &ports,
                                        config,
                                    ) {
                                        let _ = first.control.send("ERROR session-failed");
                                        let _ = control.send("ERROR session-failed");
                                        eprintln!("[server] session error: {error}");
                                    }
                                } else {
                                    if rooms.len() >= 64 {
                                        return Err("too many pending rooms".into());
                                    }
                                    control.send("WAIT")?;
                                    rooms.insert(
                                        room,
                                        Pending {
                                            id,
                                            control,
                                            since: Instant::now(),
                                        },
                                    );
                                }
                                Ok(())
                            };
                            if let Err(error) = registration() {
                                eprintln!("[server] {error}")
                            }
                        });
                    }
                    Err(e) if temporary(&e) => thread::sleep(Duration::from_millis(2)),
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            probes,
            probe_replies,
            stop,
            workers: vec![udp_worker, tcp_worker],
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn plan(control: &mut Control) -> Result<SocketAddr> {
    let line = control.recv()?;
    let f: Vec<_> = line.split_ascii_whitespace().collect();
    if f.len() != 3 || f[0] != "PLAN" {
        return Err("expected PLAN".into());
    }
    let target: SocketAddr = f[1].parse()?;
    let observed: Vec<SocketAddr> = f[2]
        .split(',')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    if !target.is_ipv4()
        || target.port() == 0
        || observed.len() != 3
        || observed.iter().any(|a| a.ip() != target.ip())
    {
        return Err("unsupported plan: need one stable public IPv4 address".into());
    }
    Ok(target)
}

fn result(control: &mut Control) -> Result<u32> {
    let line = control.recv()?;
    let f: Vec<_> = line.split_ascii_whitespace().collect();
    if f.len() != 2 || f[0] != "RESULT" {
        return Err("expected RESULT".into());
    }
    Ok(f[1].parse()?)
}

fn session(
    a: &mut Control,
    b: &mut Control,
    aid: &str,
    bid: &str,
    ports: &str,
    cfg: ServerConfig,
) -> Result<()> {
    let tag = crate::token();
    a.send(&format!(
        "MATCH {tag} A {bid} {} {} {ports}",
        cfg.rounds, cfg.round_ms
    ))?;
    b.send(&format!(
        "MATCH {tag} B {aid} {} {} {ports}",
        cfg.rounds, cfg.round_ms
    ))?;
    for round in 0..cfg.rounds {
        a.send(&format!("ROUND {round}"))?;
        b.send(&format!("ROUND {round}"))?;
        let ap = plan(a)?;
        let bp = plan(b)?;
        a.send(&format!("GO {bp}"))?;
        b.send(&format!("GO {ap}"))?;
        let ac = result(a)?;
        let bc = result(b)?;
        if ac >= 3 && bc >= 3 {
            a.send("DONE OK")?;
            b.send("DONE OK")?;
            return Ok(());
        }
        if round + 1 < cfg.rounds {
            thread::sleep(Duration::from_millis(cfg.gap_ms));
        }
    }
    a.send("DONE MISS")?;
    b.send("DONE MISS")?;
    Ok(())
}
