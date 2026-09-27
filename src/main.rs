use nat4_demo::lab;
use nat4_demo::peer::{self, PeerConfig, Strategy};
use nat4_demo::server::{Server, ServerConfig};
use nat4_demo::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HELP: &str = "nat4-demo: experimental UDP hole punching (no external crates)

  nat4-demo lab [--case all|predict|random-small|random-full|predict-on-random]
                [--seed 7] [--trace true]
  nat4-demo server [--bind 0.0.0.0:40000] [--rounds 12]
                   [--round-ms 1500] [--gap-ms 500]
  nat4-demo peer --server PUBLIC_IPV4:40000 --room ROOM --id alice
                 [--strategy predict|fanout] [--fanout 32] [--pps 200]
                 [--port-min 1024] [--port-max 65535] [--seed NUMBER]
                 [--probes IP:PORT,IP:PORT,IP:PORT]

Server ports: TCP P and UDP P, P+1, P+2. Start two peers with the same room
and DIFFERENT ids within 55 seconds. Every peer needs outbound TCP/UDP.
Success means BOTH peers received >=3 payload echoes over direct UDP.
Peer exits 0 on verified success, 2 if the budget ends without a path.
Lab exits 0 when measured outcomes match its seeded test expectations.
random-small uses a known 32-port pool; it does NOT model arbitrary CGNAT.
";

fn options(args: &[String], allowed: &[&str]) -> Result<HashMap<String, String>> {
    if args.len() % 2 != 0 {
        return Err("options must be --name value pairs".into());
    }
    let mut map = HashMap::new();
    for pair in args.chunks(2) {
        let key = pair[0].strip_prefix("--").ok_or("expected --option")?;
        if !allowed.contains(&key) {
            return Err(format!("unknown option: {}", pair[0]).into());
        }
        if map.insert(key.into(), pair[1].clone()).is_some() {
            return Err(format!("duplicate option: {key}").into());
        }
    }
    Ok(map)
}
fn value<'a>(map: &'a HashMap<String, String>, key: &str, default: &'a str) -> &'a str {
    map.get(key).map(String::as_str).unwrap_or(default)
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1)
        }
    }
}
fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|s| s == "--help" || s == "-h") {
        print!("{HELP}");
        return Ok(0);
    }
    match args[0].as_str() {
        "lab" => {
            let opts = options(&args[1..], &["case", "seed", "trace"])?;
            let case = value(&opts, "case", "all");
            let cases = if case == "all" {
                lab::CASES.to_vec()
            } else {
                vec![case]
            };
            let seed = value(&opts, "seed", "7").parse()?;
            let trace = value(&opts, "trace", "false").parse()?;
            let mut passed = true;
            for case in cases {
                passed &= lab::run(case, seed, trace)?.passed();
            }
            Ok(if passed { 0 } else { 2 })
        }
        "server" => {
            let opts = options(&args[1..], &["bind", "rounds", "round-ms", "gap-ms"])?;
            let bind: SocketAddr = value(&opts, "bind", "0.0.0.0:40000").parse()?;
            let cfg = ServerConfig {
                rounds: value(&opts, "rounds", "12").parse()?,
                round_ms: value(&opts, "round-ms", "1500").parse()?,
                gap_ms: value(&opts, "gap-ms", "500").parse()?,
            };
            let server = Server::start(bind, cfg)?;
            println!(
                "[server] TCP={} UDP={:?}; signalling/probes only, no data relay. Ctrl+C to stop.",
                server.address, server.probes
            );
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        "peer" => {
            let opts = options(
                &args[1..],
                &[
                    "server", "room", "id", "strategy", "fanout", "pps", "port-min", "port-max",
                    "seed", "probes",
                ],
            )?;
            let server = opts.get("server").ok_or("--server required")?.parse()?;
            let room = opts.get("room").ok_or("--room required")?;
            let id = opts.get("id").ok_or("--id required")?;
            let mut cfg = PeerConfig::new(server, room, id);
            cfg.strategy = match value(&opts, "strategy", "predict") {
                "predict" => Strategy::Predict,
                "fanout" => Strategy::Fanout,
                _ => return Err("unknown strategy".into()),
            };
            cfg.fanout = value(&opts, "fanout", "32").parse()?;
            cfg.pps = value(&opts, "pps", "200").parse()?;
            cfg.port_low = value(&opts, "port-min", "1024").parse()?;
            cfg.port_high = value(&opts, "port-max", "65535").parse()?;
            cfg.seed = if let Some(seed) = opts.get("seed") {
                seed.parse()?
            } else {
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64
            };
            if let Some(probes) = opts.get("probes") {
                cfg.probes = Some(
                    probes
                        .split(',')
                        .map(str::parse)
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                );
            }
            Ok(if peer::run(cfg)?.connected { 0 } else { 2 })
        }
        _ => Err("unknown command; use --help".into()),
    }
}
