//! Exercise the actual binary as three independent processes, as in the README.
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

struct ServerProcess(Child);
impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn three_process_cli_verifies_direct_udp() {
    let exe = env!("CARGO_BIN_EXE_nat4-demo");
    let child = Command::new(exe)
        .args([
            "server",
            "--bind",
            "127.0.0.1:0",
            "--rounds",
            "1",
            "--round-ms",
            "700",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut server = ServerProcess(child);
    let stdout = server.0.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let address = line
        .split_ascii_whitespace()
        .find_map(|s| s.strip_prefix("TCP="))
        .unwrap();
    let spawn_peer = |id| {
        Command::new(exe)
            .args([
                "peer", "--server", address, "--room", "cli-test", "--id", id,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let alice = spawn_peer("alice");
    let bob = spawn_peer("bob");
    for output in [
        alice.wait_with_output().unwrap(),
        bob.wait_with_output().unwrap(),
    ] {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "stdout={stdout}\nstderr={stderr}");
        assert!(stdout.contains("VERIFIED"), "{stdout}");
        assert!(stdout.contains("DIRECT_OK"), "{stdout}");
    }
}
