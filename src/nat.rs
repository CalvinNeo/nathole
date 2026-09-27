//! Userspace UDP NAT for the lab, not an OS/router configuration.
//! Mapping key: (internal IP:port, destination IP:port).
//! Inbound filtering: exact destination IP:port of that mapping only.
use crate::wire::{temporary, unpack, MAX_PACKET};
use crate::{Result, Rng};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum Allocation {
    Sequential,
    Random,
}
#[derive(Clone)]
pub struct NatConfig {
    pub name: String,
    pub public_ip: Ipv4Addr,
    pub low: u16,
    pub high: u16,
    pub allocation: Allocation,
    pub seed: u64,
    pub ttl_ms: u64,
    pub trace: bool,
}
#[derive(Default)]
pub struct NatStats {
    pub mappings: AtomicU64,
    pub outbound: AtomicU64,
    pub inbound: AtomicU64,
    pub filtered: AtomicU64,
    pub expired: AtomicU64,
    pub capacity_drops: AtomicU64,
}
pub struct Nat {
    pub gateway: SocketAddr,
    pub stats: Arc<NatStats>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
struct Mapping {
    internal: SocketAddr,
    remote: SocketAddr,
    external: UdpSocket,
    public_port: u16,
    last: Instant,
}

impl Nat {
    pub fn start(config: NatConfig) -> Result<Self> {
        if !config.public_ip.is_loopback()
            || config.low == 0
            || config.low > config.high
            || config.ttl_ms < 20
        {
            return Err("lab NAT needs loopback IP, a nonempty port pool and TTL >= 20 ms".into());
        }
        let gateway = UdpSocket::bind("127.0.0.1:0")?;
        gateway.set_nonblocking(true)?;
        let address = gateway.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let stats = Arc::new(NatStats::default());
        let worker_stats = stats.clone();
        let worker = thread::spawn(move || {
            if let Err(error) = run(gateway, config, worker_stop, worker_stats) {
                eprintln!("[nat] {error}")
            }
        });
        Ok(Self {
            gateway: address,
            stats,
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for Nat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run(
    gateway: UdpSocket,
    cfg: NatConfig,
    stop: Arc<AtomicBool>,
    stats: Arc<NatStats>,
) -> Result<()> {
    let mut maps: Vec<Mapping> = Vec::new();
    let mut next = cfg.low;
    let mut rng = Rng::new(cfg.seed);
    let mut buf = [0; MAX_PACKET];
    let ttl = Duration::from_millis(cfg.ttl_ms);
    let size = u32::from(cfg.high) - u32::from(cfg.low) + 1;
    while !stop.load(Ordering::Relaxed) {
        let before = maps.len();
        maps.retain(|m| m.last.elapsed() < ttl);
        stats
            .expired
            .fetch_add((before - maps.len()) as u64, Ordering::Relaxed);
        for _ in 0..128 {
            let (n, internal) = match gateway.recv_from(&mut buf) {
                Ok(value) => value,
                Err(e) if temporary(&e) => break,
                Err(e) => return Err(e.into()),
            };
            let Ok(text) = std::str::from_utf8(&buf[..n]) else {
                continue;
            };
            let Some((remote, body)) = unpack(text, "TO") else {
                continue;
            };
            if !internal.ip().is_loopback() || !remote.ip().is_loopback() || remote.port() == 0 {
                continue;
            }
            let index = if let Some(index) = maps
                .iter()
                .position(|m| m.internal == internal && m.remote == remote)
            {
                index
            } else {
                if maps.len() >= size as usize {
                    stats.capacity_drops.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut allocated = None;
                for _ in 0..size.saturating_mul(4) {
                    let port = match cfg.allocation {
                        Allocation::Sequential => {
                            let port = next;
                            next = if next == cfg.high { cfg.low } else { next + 1 };
                            port
                        }
                        Allocation::Random => rng.port(cfg.low, cfg.high),
                    };
                    if maps.iter().any(|m| m.public_port == port) {
                        continue;
                    }
                    if let Ok(socket) = UdpSocket::bind((cfg.public_ip, port)) {
                        socket.set_nonblocking(true)?;
                        allocated = Some((socket, port));
                        break;
                    }
                }
                let Some((external, port)) = allocated else {
                    stats.capacity_drops.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if cfg.trace {
                    println!(
                        "[{}] MAP {internal} -> {remote} => {}:{port}",
                        cfg.name, cfg.public_ip
                    )
                }
                maps.push(Mapping {
                    internal,
                    remote,
                    external,
                    public_port: port,
                    last: Instant::now(),
                });
                stats.mappings.fetch_add(1, Ordering::Relaxed);
                maps.len() - 1
            };
            maps[index].last = Instant::now();
            match maps[index].external.send_to(body.as_bytes(), remote) {
                Ok(_) => {
                    stats.outbound.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if temporary(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for map in &mut maps {
            for _ in 0..32 {
                match map.external.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if from != map.remote {
                            stats.filtered.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let Ok(text) = std::str::from_utf8(&buf[..n]) else {
                            continue;
                        };
                        let packet = format!("FROM {from}\n{text}");
                        gateway.send_to(packet.as_bytes(), map.internal)?;
                        map.last = Instant::now();
                        stats.inbound.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if temporary(&e) => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
