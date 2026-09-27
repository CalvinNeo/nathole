use nat4_demo::lab;
use nat4_demo::nat::{Allocation, Nat, NatConfig};
use nat4_demo::peer::{self, PeerConfig};
use nat4_demo::server::{Server, ServerConfig};
use nat4_demo::wire::{Control, Endpoint};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

fn nat(ip: u8, ttl_ms: u64) -> Nat {
    Nat::start(NatConfig {
        name: "test-nat".into(),
        public_ip: Ipv4Addr::new(127, 99, ip, 2),
        low: 23000,
        high: 23999,
        allocation: Allocation::Sequential,
        seed: 1,
        ttl_ms,
        trace: false,
    })
    .unwrap()
}
fn udp() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
}
fn receive(endpoint: &Endpoint, milliseconds: u64) -> Option<(String, SocketAddr)> {
    let deadline = Instant::now() + Duration::from_millis(milliseconds);
    while Instant::now() < deadline {
        if let Some(packet) = endpoint.recv().unwrap() {
            return Some(packet);
        }
        thread::sleep(Duration::from_millis(2));
    }
    None
}
fn outbound(endpoint: &Endpoint, remote: &UdpSocket) -> SocketAddr {
    endpoint
        .send("outbound", remote.local_addr().unwrap())
        .unwrap();
    let mut bytes = [0; 128];
    let (_, observed) = remote.recv_from(&mut bytes).unwrap();
    observed
}

#[test]
fn nat_mapping_depends_on_internal_socket_and_remote_ip_and_port() {
    let nat = nat(1, 5000);
    let a = Endpoint::bind(Some(nat.gateway)).unwrap();
    let b = Endpoint::bind(Some(nat.gateway)).unwrap();
    let remote1 = udp();
    let remote2 = udp();
    let remote3 = UdpSocket::bind((
        Ipv4Addr::new(127, 0, 0, 2),
        remote1.local_addr().unwrap().port(),
    ))
    .unwrap();
    remote3
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let first = outbound(&a, &remote1);
    assert_eq!(
        first,
        outbound(&a, &remote1),
        "same 4-tuple must reuse the mapping"
    );
    assert_ne!(
        first,
        outbound(&a, &remote2),
        "new destination port must change the mapping"
    );
    assert_ne!(
        first,
        outbound(&a, &remote3),
        "new destination IP must change the mapping"
    );
    assert_ne!(
        first,
        outbound(&b, &remote1),
        "new internal socket must get its own mapping"
    );
}

#[test]
fn nat_rejects_wrong_source_ip_or_port_and_accepts_exact_remote() {
    let nat = nat(2, 5000);
    let internal = Endpoint::bind(Some(nat.gateway)).unwrap();
    let legitimate = udp();
    let wrong_port = udp();
    let wrong_ip = UdpSocket::bind((
        Ipv4Addr::new(127, 0, 0, 2),
        legitimate.local_addr().unwrap().port(),
    ))
    .unwrap();
    let public = outbound(&internal, &legitimate);
    wrong_port.send_to(b"wrong-port", public).unwrap();
    wrong_ip.send_to(b"wrong-ip", public).unwrap();
    assert!(
        receive(&internal, 80).is_none(),
        "strict filtering must not silently become cone NAT"
    );
    legitimate.send_to(b"valid", public).unwrap();
    assert_eq!(
        receive(&internal, 500),
        Some(("valid".into(), legitimate.local_addr().unwrap()))
    );
    assert_eq!(nat.stats.filtered.load(Ordering::Relaxed), 2);
}

#[test]
fn expired_nat_mapping_no_longer_accepts_even_the_correct_remote() {
    let nat = nat(3, 100);
    let internal = Endpoint::bind(Some(nat.gateway)).unwrap();
    let remote = udp();
    let public = outbound(&internal, &remote);
    let deadline = Instant::now() + Duration::from_secs(2);
    while nat.stats.expired.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(nat.stats.expired.load(Ordering::Relaxed), 1);
    remote.send_to(b"too-late", public).unwrap();
    assert!(receive(&internal, 80).is_none());
}

#[test]
fn coordinator_udp_only_answers_address_probes() {
    let server = Server::start("127.0.0.1:0".parse().unwrap(), ServerConfig::default()).unwrap();
    let client = udp();
    client
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    client
        .send_to(
            b"N4 PING session room alice 0 nonce 1 payload",
            server.probes[0],
        )
        .unwrap();
    let mut buf = [0; 256];
    assert!(
        client.recv_from(&mut buf).is_err(),
        "data must never be echoed or relayed by coordinator"
    );
    client
        .send_to(b"N4 WHO transaction", server.probes[0])
        .unwrap();
    let (n, _) = client.recv_from(&mut buf).unwrap();
    assert!(std::str::from_utf8(&buf[..n])
        .unwrap()
        .starts_with("N4 SEEN transaction "));
}

#[test]
fn real_socket_transport_works_without_the_nat_adapter() {
    let server = Server::start(
        "127.0.0.1:0".parse().unwrap(),
        ServerConfig {
            rounds: 1,
            round_ms: 400,
            gap_ms: 0,
        },
    )
    .unwrap();
    let a = PeerConfig::new(server.address, "direct_test", "alice");
    let b = PeerConfig::new(server.address, "direct_test", "bob");
    let a = thread::spawn(move || peer::run(a).unwrap());
    let b = thread::spawn(move || peer::run(b).unwrap());
    let a = a.join().unwrap();
    let b = b.join().unwrap();
    assert!(a.connected && b.connected);
    assert!(a.attempt.pongs >= 3 && b.attempt.pongs >= 3);
}

#[test]
fn coordinator_success_message_cannot_fake_udp_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = PeerConfig::new(listener.local_addr().unwrap(), "proof_test", "alice");
    let fake = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut control = Control::new(stream).unwrap();
        control.recv().unwrap();
        control
            .send("MATCH session A bob 1 200 33001,33002,33003")
            .unwrap();
        control.send("DONE OK").unwrap();
    });
    let result = peer::run(cfg).unwrap();
    fake.join().unwrap();
    assert!(!result.connected);
    assert_eq!(result.attempt.pongs, 0);
}

#[test]
fn two_strict_sequential_nats_establish_a_direct_path() {
    let result = lab::run("predict", 7, false).unwrap();
    assert!(result.passed() && result.a.connected && result.b.connected);
    assert_eq!(
        result.mappings, 8,
        "three discovery mappings and one peer mapping per NAT"
    );
}

#[test]
fn two_strict_random_nats_can_connect_in_an_explicit_small_pool() {
    let result = lab::run("random-small", 7, false).unwrap();
    assert!(result.passed() && result.a.connected && result.b.connected);
    assert!(
        result.filtered > 0,
        "most source-port guesses should actually be rejected"
    );
}

#[test]
fn unrestricted_random_pool_does_not_get_reported_as_a_success() {
    let result = lab::run("random-full", 7, false).unwrap();
    assert!(result.passed() && !result.a.connected && !result.b.connected);
}

#[test]
fn next_port_prediction_does_not_magically_solve_random_allocation() {
    let result = lab::run("predict-on-random", 7, false).unwrap();
    assert!(result.passed() && !result.a.connected && !result.b.connected);
}
