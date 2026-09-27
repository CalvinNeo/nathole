use crate::nat::{Allocation, Nat, NatConfig};
use crate::peer::{self, PeerConfig, PeerResult, Strategy};
use crate::server::{Server, ServerConfig};
use crate::Result;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

pub const CASES: [&str; 4] = [
    "predict",
    "random-small",
    "random-full",
    "predict-on-random",
];
#[derive(Debug)]
pub struct LabResult {
    pub case: String,
    pub expected: bool,
    pub a: PeerResult,
    pub b: PeerResult,
    pub mappings: u64,
    pub filtered: u64,
    pub capacity_drops: u64,
}
impl LabResult {
    pub fn passed(&self) -> bool {
        self.a.connected == self.expected
            && self.b.connected == self.expected
            && self.capacity_drops == 0
    }
}

pub fn run(case: &str, seed: u64, trace: bool) -> Result<LabResult> {
    static INSTANCE: AtomicU64 = AtomicU64::new(0);
    let octet = 1 + (INSTANCE.fetch_add(1, Ordering::Relaxed) % 240) as u8;
    let (allocation, strategy, low, high, rounds, expected) = match case {
        "predict" => (
            Allocation::Sequential,
            Strategy::Predict,
            20000,
            21023,
            2,
            true,
        ),
        "random-small" => (Allocation::Random, Strategy::Fanout, 40000, 40031, 8, true),
        "random-full" => (Allocation::Random, Strategy::Fanout, 1024, 65535, 2, false),
        "predict-on-random" => (Allocation::Random, Strategy::Predict, 1024, 65535, 2, false),
        _ => return Err(format!("unknown lab case: {case}").into()),
    };
    println!(
        "\n[lab] case={case} seed={seed} NAT=APDM+APDF allocation={allocation:?} pool={low}-{high}"
    );
    if case == "random-small" {
        println!("[lab] CONTROLLED experiment: the peers are explicitly told the 32-port pool. This is NOT a full-range Internet success claim.");
    }
    if !expected {
        println!("[lab] expected MISS for this seed/budget, not a proof of impossibility");
    }
    let server = Server::start(
        "127.0.0.1:0".parse()?,
        ServerConfig {
            rounds,
            round_ms: 450,
            gap_ms: 850,
        },
    )?;
    let make_nat = |name: &str, last: u8, salt: u64| {
        Nat::start(NatConfig {
            name: name.into(),
            public_ip: Ipv4Addr::new(127, 64, octet, last),
            low,
            high,
            allocation,
            seed: seed.wrapping_add(salt),
            ttl_ms: 700,
            trace,
        })
    };
    let nat_a = make_nat("NAT-A", 2, 901)?;
    let nat_b = make_nat("NAT-B", 3, 1901)?;
    let room = crate::token();
    let make_peer = |id: &str, gateway, salt: u64| {
        let mut cfg = PeerConfig::new(server.address, &room, id);
        cfg.strategy = strategy;
        cfg.fanout = 24;
        cfg.pps = 800;
        cfg.port_low = low;
        cfg.port_high = high;
        cfg.seed = seed.wrapping_add(salt);
        cfg.gateway = Some(gateway);
        cfg
    };
    let a_cfg = make_peer("alice", nat_a.gateway, 3109);
    let b_cfg = make_peer("bob", nat_b.gateway, 7207);
    let a = thread::spawn(move || peer::run(a_cfg));
    let b = thread::spawn(move || peer::run(b_cfg));
    let a = a.join().map_err(|_| "peer A panicked")?;
    let b = b.join().map_err(|_| "peer B panicked")?;
    let (a, b) = (a?, b?);
    let mappings =
        nat_a.stats.mappings.load(Ordering::Relaxed) + nat_b.stats.mappings.load(Ordering::Relaxed);
    let filtered =
        nat_a.stats.filtered.load(Ordering::Relaxed) + nat_b.stats.filtered.load(Ordering::Relaxed);
    let capacity_drops = nat_a.stats.capacity_drops.load(Ordering::Relaxed)
        + nat_b.stats.capacity_drops.load(Ordering::Relaxed);
    let result = LabResult {
        case: case.into(),
        expected,
        a,
        b,
        mappings,
        filtered,
        capacity_drops,
    };
    println!("[lab] {} case={} direct={} a_pongs={} b_pongs={} mappings={} filtered={} capacity_drops={} server_data_relay=0",
        if result.passed() { "PASS" } else { "UNEXPECTED" }, case, result.a.connected && result.b.connected,
        result.a.attempt.pongs, result.b.attempt.pongs, mappings, filtered, capacity_drops);
    Ok(result)
}
