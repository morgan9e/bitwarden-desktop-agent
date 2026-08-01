
use std::io::{self, Read, Write};

use snow::{Builder, HandshakeState, TransportState};

pub const PATTERN_EVAL: u8 = 0x01;
pub const PATTERN_ENROLL: u8 = 0x02;

pub const IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const NK_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

pub const MAX_FRAME: usize = 65535;

pub const KEY_LEN: usize = 32;

pub fn public_key(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let secret = x25519_dalek::StaticSecret::from(*private);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

pub fn generate_private_key() -> [u8; KEY_LEN] {
    let secret = x25519_dalek::StaticSecret::random_from_rng(crate::rng::OsRng);
    secret.to_bytes()
}


pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}


pub struct Channel<S> {
    stream: S,
    transport: TransportState,
}

impl<S: Read + Write> Channel<S> {
    pub fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut buf = vec![0u8; plaintext.len() + 64];
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(other)?;
        write_frame(&mut self.stream, &buf[..n])
    }

    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        let frame = read_frame(&mut self.stream)?;
        let mut buf = vec![0u8; frame.len()];
        let n = self
            .transport
            .read_message(&frame, &mut buf)
            .map_err(other)?;
        buf.truncate(n);
        Ok(buf)
    }
}

fn other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn finish<S: Read + Write>(hs: HandshakeState, stream: S) -> io::Result<Channel<S>> {
    let transport = hs.into_transport_mode().map_err(other)?;
    Ok(Channel { stream, transport })
}


pub fn client_eval<S: Read + Write>(
    mut stream: S,
    local_private: &[u8; KEY_LEN],
    server_public: &[u8; KEY_LEN],
) -> io::Result<Channel<S>> {
    stream.write_all(&[PATTERN_EVAL])?;
    let mut hs = Builder::new(IK_PARAMS.parse().map_err(other)?)
        .local_private_key(local_private)
        .map_err(other)?
        .remote_public_key(server_public)
        .map_err(other)?
        .build_initiator()
        .map_err(other)?;
    handshake_initiator(&mut stream, &mut hs)?;
    finish(hs, stream)
}

pub fn client_enroll<S: Read + Write>(
    mut stream: S,
    server_public: &[u8; KEY_LEN],
) -> io::Result<Channel<S>> {
    stream.write_all(&[PATTERN_ENROLL])?;
    let mut hs = Builder::new(NK_PARAMS.parse().map_err(other)?)
        .remote_public_key(server_public)
        .map_err(other)?
        .build_initiator()
        .map_err(other)?;
    handshake_initiator(&mut stream, &mut hs)?;
    finish(hs, stream)
}

fn handshake_initiator<S: Read + Write>(stream: &mut S, hs: &mut HandshakeState) -> io::Result<()> {
    let mut buf = [0u8; MAX_FRAME];
    let n = hs.write_message(&[], &mut buf).map_err(other)?;
    write_frame(stream, &buf[..n])?;
    let reply = read_frame(stream)?;
    hs.read_message(&reply, &mut buf).map_err(other)?;
    if !hs.is_handshake_finished() {
        return Err(other("handshake did not complete"));
    }
    Ok(())
}


pub struct Accepted<S> {
    pub channel: Channel<S>,
    pub pattern: u8,
    pub client_static: Option<[u8; KEY_LEN]>,
}

pub fn server_accept<S: Read + Write>(
    mut stream: S,
    local_private: &[u8; KEY_LEN],
) -> io::Result<Accepted<S>> {
    let mut selector = [0u8; 1];
    stream.read_exact(&mut selector)?;

    let params = match selector[0] {
        PATTERN_EVAL => IK_PARAMS,
        PATTERN_ENROLL => NK_PARAMS,
        other_byte => {
            return Err(other(format!("unknown pattern selector {other_byte:#04x}")));
        }
    };

    let mut hs = Builder::new(params.parse().map_err(other)?)
        .local_private_key(local_private)
        .map_err(other)?
        .build_responder()
        .map_err(other)?;

    let mut buf = [0u8; MAX_FRAME];
    let first = read_frame(&mut stream)?;
    hs.read_message(&first, &mut buf).map_err(other)?;
    let n = hs.write_message(&[], &mut buf).map_err(other)?;
    write_frame(&mut stream, &buf[..n])?;
    if !hs.is_handshake_finished() {
        return Err(other("handshake did not complete"));
    }

    let client_static = hs.get_remote_static().and_then(|s| {
        let mut k = [0u8; KEY_LEN];
        (s.len() == KEY_LEN).then(|| {
            k.copy_from_slice(s);
            k
        })
    });

    Ok(Accepted {
        pattern: selector[0],
        client_static,
        channel: finish(hs, stream)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let client = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server, _) = l.accept().unwrap();
        (client.join().unwrap(), server)
    }

    #[test]
    fn ik_round_trip_authenticates_the_client() {
        let server_priv = generate_private_key();
        let server_pub = public_key(&server_priv);
        let client_priv = generate_private_key();
        let client_pub = public_key(&client_priv);

        let (c, s) = pair();
        let t = std::thread::spawn(move || {
            let mut ch = client_eval(c, &client_priv, &server_pub).unwrap();
            ch.send(b"ping").unwrap();
            ch.recv().unwrap()
        });

        let mut acc = server_accept(s, &server_priv).unwrap();
        assert_eq!(acc.pattern, PATTERN_EVAL);
        assert_eq!(acc.client_static.unwrap(), client_pub);
        assert_eq!(acc.channel.recv().unwrap(), b"ping");
        acc.channel.send(b"pong").unwrap();

        assert_eq!(t.join().unwrap(), b"pong");
    }

    #[test]
    fn nk_round_trip_carries_no_client_identity() {
        let server_priv = generate_private_key();
        let server_pub = public_key(&server_priv);

        let (c, s) = pair();
        let t = std::thread::spawn(move || {
            let mut ch = client_enroll(c, &server_pub).unwrap();
            ch.send(b"enroll").unwrap();
        });

        let mut acc = server_accept(s, &server_priv).unwrap();
        assert_eq!(acc.pattern, PATTERN_ENROLL);
        assert!(acc.client_static.is_none());
        assert_eq!(acc.channel.recv().unwrap(), b"enroll");
        t.join().unwrap();
    }

    #[test]
    fn wrong_server_key_fails_the_handshake() {
        let server_priv = generate_private_key();
        let wrong_pub = public_key(&generate_private_key());
        let client_priv = generate_private_key();

        let (c, s) = pair();
        let t = std::thread::spawn(move || {
            let mut ch = match client_eval(c, &client_priv, &wrong_pub) {
                Ok(ch) => ch,
                Err(_) => return true,
            };
            ch.send(b"ping").is_err() || ch.recv().is_err()
        });
        let _ = server_accept(s, &server_priv);
        assert!(t.join().unwrap());
    }
}
