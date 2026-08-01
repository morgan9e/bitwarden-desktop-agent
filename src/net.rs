//! Client transport to `bw-keyd`.
//!
//! Connect, handshake, one request, one response, close. No resumption, no
//! long-lived sessions, no retry: a retry would silently cost a second budget
//! token for the same PIN attempt.

use std::fmt;
use std::net::TcpStream;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use bw_proto::msg::{Request, Response, VERSION};
use bw_proto::noise;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 8 * 1024;

pub enum NetError {
    /// Operational, and worth saying plainly: the fallback is the master
    /// password, and no vault data is at risk.
    Unreachable(String),
    /// Revoked, unknown, or pending. The server does not say which, by design.
    Denied,
    Throttled(u64),
    Protocol(String),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(e) => {
                write!(f, "server unreachable ({e}) — unlock with your master password")
            }
            Self::Denied => write!(
                f,
                "this device is not authorised — unlock with your master password"
            ),
            Self::Throttled(s) => {
                let mins = (*s + 59) / 60;
                write!(f, "too many attempts, retry in {mins} minute(s)")
            }
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

fn connect(addr: &str) -> Result<TcpStream, NetError> {
    let stream =
        TcpStream::connect(addr).map_err(|e| NetError::Unreachable(format!("{addr}: {e}")))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    stream.set_nodelay(true).ok();
    Ok(stream)
}

fn exchange<S: std::io::Read + std::io::Write>(
    channel: &mut noise::Channel<S>,
    request: &Request,
) -> Result<Response, NetError> {
    let body = serde_json::to_vec(request).map_err(|e| NetError::Protocol(e.to_string()))?;
    channel
        .send(&body)
        .map_err(|e| NetError::Unreachable(e.to_string()))?;
    let raw = channel
        .recv()
        .map_err(|e| NetError::Unreachable(e.to_string()))?;
    if raw.len() > MAX_RESPONSE {
        return Err(NetError::Protocol("response too large".into()));
    }
    let response: Response =
        serde_json::from_slice(&raw).map_err(|e| NetError::Protocol(e.to_string()))?;
    Ok(response)
}

/// §5.4 step 3. `Noise_NK`: the server's static key comes from the enrollment
/// token and is pinned; this device's static key is not yet trusted, so it
/// travels in the request body rather than in the handshake.
pub fn enroll(
    addr: &str,
    server_pub: &[u8; 32],
    token: &str,
    static_pub: &[u8; 32],
    device_id: &str,
    label: &str,
) -> Result<(), NetError> {
    let stream = connect(addr)?;
    let mut channel = noise::client_enroll(stream, server_pub)
        .map_err(|e| NetError::Unreachable(format!("handshake: {e}")))?;

    let request = Request::enroll(
        token.to_string(),
        B64.encode(static_pub),
        device_id.to_string(),
        label.to_string(),
    );

    match exchange(&mut channel, &request)? {
        Response::Enrolled { v } if v == VERSION => Ok(()),
        Response::Denied { .. } => Err(NetError::Denied),
        other => Err(NetError::Protocol(format!(
            "unexpected response to enroll: {other:?}"
        ))),
    }
}

/// §5.3 steps 4–7. One round trip, one budget token, one candidate evaluation.
/// Returns the evaluated element and the device's remaining budget.
pub fn eval(
    addr: &str,
    server_pub: &[u8; 32],
    identity: &[u8; 32],
    blinded: &[u8; 32],
) -> Result<([u8; 32], u32), NetError> {
    let stream = connect(addr)?;
    // A pinned-key mismatch fails here, and is never a prompt to accept.
    let mut channel = noise::client_eval(stream, identity, server_pub)
        .map_err(|e| NetError::Unreachable(format!("handshake: {e}")))?;

    match exchange(&mut channel, &Request::eval(B64.encode(blinded)))? {
        Response::Ok {
            v,
            evaluated,
            tokens_left,
        } if v == VERSION => {
            let bytes = B64
                .decode(&evaluated)
                .map_err(|_| NetError::Protocol("evaluated element is not base64".into()))?;
            let element = <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| NetError::Protocol("evaluated element is not 32 bytes".into()))?;
            Ok((element, tokens_left))
        }
        Response::Throttled { retry_after_s, .. } => Err(NetError::Throttled(retry_after_s)),
        Response::Denied { .. } => Err(NetError::Denied),
        other => Err(NetError::Protocol(format!(
            "unexpected response to eval: {other:?}"
        ))),
    }
}
