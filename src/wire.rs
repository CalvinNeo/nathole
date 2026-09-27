use crate::Result;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_PACKET: usize = 2048;

pub fn temporary(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

/// In the lab, only this adapter knows the gateway. The punching algorithm
/// sees normal (payload, remote-address) datagrams, never the NAT mapping table.
pub struct Endpoint {
    socket: UdpSocket,
    gateway: Option<SocketAddr>,
}

impl Endpoint {
    pub fn bind(gateway: Option<SocketAddr>) -> Result<Self> {
        let socket = UdpSocket::bind(if gateway.is_some() {
            "127.0.0.1:0"
        } else {
            "0.0.0.0:0"
        })?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, gateway })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn send(&self, payload: &str, to: SocketAddr) -> io::Result<()> {
        let result = if let Some(gateway) = self.gateway {
            self.socket
                .send_to(format!("TO {to}\n{payload}").as_bytes(), gateway)
        } else {
            self.socket.send_to(payload.as_bytes(), to)
        };
        match result {
            Ok(_) => Ok(()),
            Err(e) if temporary(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }
    pub fn recv(&self) -> io::Result<Option<(String, SocketAddr)>> {
        let mut buf = [0; MAX_PACKET];
        let (n, from) = match self.socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(e) if temporary(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let Ok(text) = std::str::from_utf8(&buf[..n]) else {
            return Ok(None);
        };
        if let Some(gateway) = self.gateway {
            if from != gateway {
                return Ok(None);
            }
            return Ok(unpack(text, "FROM").map(|(addr, body)| (body.to_owned(), addr)));
        }
        Ok(Some((text.to_owned(), from)))
    }
}

pub fn unpack<'a>(text: &'a str, prefix: &str) -> Option<(SocketAddr, &'a str)> {
    let (header, body) = text.split_once('\n')?;
    let (kind, address) = header.split_once(' ')?;
    if kind != prefix || body.len() > 1500 {
        return None;
    }
    let address: SocketAddr = address.parse().ok()?;
    if !address.is_ipv4() {
        return None;
    }
    Some((address, body))
}

pub fn probe(endpoint: &Endpoint, server: SocketAddr) -> Result<SocketAddr> {
    let nonce = crate::token();
    let request = format!("N4 WHO {nonce}");
    let prefix = format!("N4 SEEN {nonce} ");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            endpoint.send(&request, server)?;
            next_send = Instant::now() + Duration::from_millis(200);
        }
        if let Some((body, from)) = endpoint.recv()? {
            if from == server {
                if let Some(address) = body.strip_prefix(&prefix) {
                    let address: SocketAddr = address.parse()?;
                    if address.is_ipv4() {
                        return Ok(address);
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    Err(format!("UDP probe timed out: {server}; check UDP ports / firewall / server").into())
}

pub struct Control {
    reader: BufReader<TcpStream>,
}
impl Control {
    pub fn new(stream: TcpStream) -> Result<Self> {
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(Self {
            reader: BufReader::new(stream),
        })
    }
    pub fn send(&mut self, line: &str) -> Result<()> {
        writeln!(self.reader.get_mut(), "{line}")?;
        Ok(())
    }
    pub fn recv(&mut self) -> Result<String> {
        let mut line = String::new();
        let n = self.reader.by_ref().take(4097).read_line(&mut line)?;
        if n == 0 {
            return Err("coordinator closed the connection".into());
        }
        if n > 4096 || !line.ends_with('\n') {
            return Err("invalid control line".into());
        }
        Ok(line.trim().to_owned())
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: String,
    pub session: String,
    pub room: String,
    pub from: String,
    pub round: usize,
    pub nonce: String,
    pub seq: u32,
    pub body: String,
}
impl Packet {
    pub fn encode(&self) -> String {
        format!(
            "N4 {} {} {} {} {} {} {} {}",
            self.kind,
            self.session,
            self.room,
            self.from,
            self.round,
            self.nonce,
            self.seq,
            self.body
        )
    }
    pub fn decode(text: &str) -> Option<Self> {
        let fields: Vec<_> = text.split_ascii_whitespace().collect();
        if fields.len() != 9
            || fields[0] != "N4"
            || !matches!(fields[1], "PUNCH" | "ACK" | "PING" | "PONG")
        {
            return None;
        }
        if !fields[2..5].iter().all(|s| crate::valid_label(s))
            || !crate::valid_label(fields[6])
            || !crate::valid_label(fields[8])
        {
            return None;
        }
        Some(Self {
            kind: fields[1].into(),
            session: fields[2].into(),
            room: fields[3].into(),
            from: fields[4].into(),
            round: fields[5].parse().ok()?,
            nonce: fields[6].into(),
            seq: fields[7].parse().ok()?,
            body: fields[8].into(),
        })
    }
}
