use crate::wire::{probe, Control, Endpoint, Packet};
use crate::{Result, Rng};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    Predict,
    Fanout,
}
#[derive(Clone)]
pub struct PeerConfig {
    pub server: SocketAddr,
    pub room: String,
    pub id: String,
    pub strategy: Strategy,
    pub fanout: usize,
    pub pps: u32,
    pub port_low: u16,
    pub port_high: u16,
    pub seed: u64,
    pub probes: Option<Vec<SocketAddr>>,
    pub gateway: Option<SocketAddr>,
}
impl PeerConfig {
    pub fn new(server: SocketAddr, room: &str, id: &str) -> Self {
        Self {
            server,
            room: room.into(),
            id: id.into(),
            strategy: Strategy::Predict,
            fanout: 32,
            pps: 200,
            port_low: 1024,
            port_high: 65535,
            seed: 1,
            probes: None,
            gateway: None,
        }
    }
}
#[derive(Debug, Clone, Default)]
pub struct Attempt {
    pub round: usize,
    pub pongs: u32,
    pub remote: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
    pub mean_rtt_ms: f64,
}
#[derive(Debug)]
pub struct PeerResult {
    pub connected: bool,
    pub attempt: Attempt,
}

/// A deliberately small estimator. This is a hypothesis, not NAT classification.
pub fn predict(samples: &[SocketAddr]) -> Result<(SocketAddr, &'static str)> {
    if samples.len() != 3 || samples.iter().any(|a| a.ip() != samples[0].ip()) {
        return Err("prediction requires three samples on one public IPv4 address".into());
    }
    let p: Vec<i32> = samples.iter().map(|a| i32::from(a.port())).collect();
    let d1 = p[1] - p[0];
    let d2 = p[2] - p[1];
    let (step, label) = if d1 == 0 && d2 == 0 {
        (0, "stable-mapping")
    } else if d1 == d2 && d1 != 0 && d1.abs() <= 64 {
        (d1, "sequential-hypothesis")
    } else {
        (1, "irregular-next-port-guess")
    };
    let next = p[2] + step;
    if !(1..=65535).contains(&next) {
        return Err("predicted port out of range".into());
    }
    Ok((SocketAddr::new(samples[2].ip(), next as u16), label))
}

pub fn run(cfg: PeerConfig) -> Result<PeerResult> {
    if !cfg.server.is_ipv4()
        || !crate::valid_label(&cfg.room)
        || !crate::valid_label(&cfg.id)
        || cfg.id.len() > 32
        || !(1..=512).contains(&cfg.fanout)
        || !(1..=2000).contains(&cfg.pps)
        || cfg.port_low == 0
        || u32::from(cfg.port_high) < u32::from(cfg.port_low) + 3
    {
        return Err("invalid peer options".into());
    }
    let stream = TcpStream::connect_timeout(&cfg.server, Duration::from_secs(5))?;
    let mut control = Control::new(stream)?;
    control.send(&format!("JOIN {} {}", cfg.room, cfg.id))?;
    let matched = loop {
        let line = control.recv()?;
        if line == "WAIT" {
            println!(
                "[{}] waiting for the second peer in room {}",
                cfg.id, cfg.room
            );
            continue;
        }
        break line;
    };
    let f: Vec<_> = matched.split_ascii_whitespace().collect();
    if f.len() != 7 || f[0] != "MATCH" {
        return Err(format!("coordinator: {matched}").into());
    }
    let session = f[1].to_owned();
    let other = f[3].to_owned();
    let rounds: usize = f[4].parse()?;
    let round_ms: u64 = f[5].parse()?;
    if !crate::valid_label(&session)
        || !crate::valid_label(&other)
        || !(1..=1000).contains(&rounds)
        || !(200..=30000).contains(&round_ms)
    {
        return Err("invalid MATCH parameters".into());
    }
    let default_probes = f[6]
        .split(',')
        .map(|p| Ok(SocketAddr::new(cfg.server.ip(), p.parse()?)))
        .collect::<Result<Vec<_>>>()?;
    let probes = cfg.probes.clone().unwrap_or(default_probes);
    if probes.len() != 3
        || probes.iter().any(|a| !a.is_ipv4())
        || probes.iter().collect::<HashSet<_>>().len() != 3
    {
        return Err("provide exactly three distinct IPv4 probe endpoints".into());
    }
    let mut rng = Rng::new(cfg.seed);
    let mut last = Attempt::default();
    let mut expected_round = 0;
    loop {
        let line = control.recv()?;
        if line == "DONE OK" || line == "DONE MISS" {
            let connected = line == "DONE OK" && last.pongs >= 3;
            println!(
                "[{}] {} pongs={} remote={:?}",
                cfg.id,
                if connected {
                    "DIRECT_OK"
                } else {
                    "NO_DIRECT_PATH"
                },
                last.pongs,
                last.remote
            );
            return Ok(PeerResult {
                connected,
                attempt: last,
            });
        }
        let Some(value) = line.strip_prefix("ROUND ") else {
            return Err(format!("coordinator: {line}").into());
        };
        let round: usize = value.parse()?;
        if round != expected_round || round >= rounds {
            return Err("unexpected round number".into());
        }
        expected_round += 1;
        let discovery = Endpoint::bind(cfg.gateway)?;
        let mut samples = Vec::new();
        for address in &probes {
            samples.push(probe(&discovery, *address)?);
        }
        let (prediction, description) = match predict(&samples) {
            Ok(hypothesis) => hypothesis,
            Err(_)
                if cfg.strategy == Strategy::Fanout
                    && samples.iter().all(|s| s.ip() == samples[0].ip()) =>
            {
                // Fanout only needs the public IP. A last observation at port
                // 65535 must not fail because an unused prediction overflows.
                (samples[2], "no-valid-next-port-prediction")
            }
            Err(error) => return Err(error),
        };
        let (sockets, advertised) = match cfg.strategy {
            Strategy::Predict => (vec![discovery], prediction),
            Strategy::Fanout => {
                // Guess our own future PUBLIC receive port. It is not a bind()
                // request to the NAT. The other peer aims at this guess.
                let mut port = rng.port(cfg.port_low, cfg.port_high);
                while samples.iter().any(|a| a.port() == port) {
                    port = rng.port(cfg.port_low, cfg.port_high);
                }
                let sockets = (0..cfg.fanout)
                    .map(|_| Endpoint::bind(cfg.gateway))
                    .collect::<Result<Vec<_>>>()?;
                (sockets, SocketAddr::new(samples[2].ip(), port))
            }
        };
        let sample_text = samples
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "[{}] round={} samples=[{}] {} strategy={:?} advertised={} sockets={}",
            cfg.id,
            round + 1,
            sample_text,
            description,
            cfg.strategy,
            advertised,
            sockets.len()
        );
        control.send(&format!("PLAN {advertised} {sample_text}"))?;
        let go = control.recv()?;
        let Some(remote) = go.strip_prefix("GO ") else {
            return Err(format!("coordinator: {go}").into());
        };
        let remote: SocketAddr = remote.parse()?;
        if !remote.is_ipv4() || remote.port() == 0 {
            return Err("invalid peer address".into());
        }
        last = punch(
            &cfg,
            &sockets,
            remote,
            &session,
            &other,
            round,
            Duration::from_millis(round_ms),
        )?;
        control.send(&format!("RESULT {}", last.pongs))?;
        // Keep all sockets alive until the common round ends. Success is only
        // declared by the coordinator after BOTH peers prove >= 3 round trips.
    }
}

struct SocketState {
    nonce: String,
    remote: Option<SocketAddr>,
    seq: u32,
    pending: HashMap<u32, Instant>,
    pongs: u32,
    total_rtt: Duration,
}

fn punch(
    cfg: &PeerConfig,
    sockets: &[Endpoint],
    target: SocketAddr,
    session: &str,
    other: &str,
    round: usize,
    duration: Duration,
) -> Result<Attempt> {
    let mut states: Vec<_> = sockets
        .iter()
        .map(|_| SocketState {
            nonce: crate::token(),
            remote: None,
            seq: 0,
            pending: HashMap::new(),
            pongs: 0,
            total_rtt: Duration::ZERO,
        })
        .collect();
    let started = Instant::now();
    let mut next_send = started;
    let interval = Duration::from_secs_f64(1.0 / f64::from(cfg.pps));
    let mut cursor = 0;
    while started.elapsed() < duration {
        for (index, socket) in sockets.iter().enumerate() {
            let state = &mut states[index];
            for _ in 0..16 {
                let Some((text, from)) = socket.recv()? else {
                    break;
                };
                let Some(mut packet) = Packet::decode(&text) else {
                    continue;
                };
                if packet.session != session
                    || packet.room != cfg.room
                    || packet.from != other
                    || packet.round != round
                {
                    continue;
                }
                match packet.kind.as_str() {
                    "PUNCH" => {
                        packet.kind = "ACK".into();
                        packet.from = cfg.id.clone();
                        socket.send(&packet.encode(), from)?;
                    }
                    "ACK" if packet.nonce == state.nonce => {
                        state.remote = Some(from);
                    }
                    "PING" if packet.body == format!("hello-from-{other}") => {
                        packet.kind = "PONG".into();
                        packet.from = cfg.id.clone();
                        socket.send(&packet.encode(), from)?;
                    }
                    "PONG"
                        if packet.nonce == state.nonce
                            && packet.body == format!("hello-from-{}", cfg.id)
                            && state.remote == Some(from) =>
                    {
                        if let Some(sent) = state.pending.remove(&packet.seq) {
                            state.pongs += 1;
                            state.total_rtt += sent.elapsed();
                            if state.pongs == 3 {
                                println!("[{}] VERIFIED round={} local={} remote={} payload={} round_trips=3",
                                    cfg.id, round + 1, socket.local_addr()?, from, packet.body);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if Instant::now() >= next_send {
            let state = &mut states[cursor];
            let (kind, to, body) = if let Some(remote) = state.remote {
                state.seq += 1;
                state.pending.insert(state.seq, Instant::now());
                state
                    .pending
                    .retain(|_, sent| sent.elapsed() < Duration::from_secs(5));
                ("PING", remote, format!("hello-from-{}", cfg.id))
            } else {
                ("PUNCH", target, "probe".into())
            };
            let packet = Packet {
                kind: kind.into(),
                session: session.into(),
                room: cfg.room.clone(),
                from: cfg.id.clone(),
                round,
                nonce: state.nonce.clone(),
                seq: state.seq,
                body,
            };
            sockets[cursor].send(&packet.encode(), to)?;
            cursor = (cursor + 1) % sockets.len();
            next_send = Instant::now() + interval;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let (index, best) = states
        .iter()
        .enumerate()
        .max_by_key(|(_, s)| s.pongs)
        .unwrap();
    Ok(Attempt {
        round: round + 1,
        pongs: best.pongs,
        remote: best.remote,
        local: Some(sockets[index].local_addr()?),
        mean_rtt_ms: if best.pongs == 0 {
            0.0
        } else {
            best.total_rtt.as_secs_f64() * 1000.0 / f64::from(best.pongs)
        },
    })
}
