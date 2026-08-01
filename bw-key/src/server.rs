
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use bw_proto::msg::{Request, Response, VERSION};
use bw_proto::noise::{self, PATTERN_ENROLL, PATTERN_EVAL};

use crate::{alert, budget, db, enroll, log};

pub const DENIED_FLOOR: Duration = Duration::from_millis(120);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REQUEST: usize = 8 * 1024;

pub fn handle(
    stream: TcpStream,
    store: &db::Db,
    key: &[u8; 32],
    rates: &alert::Rates,
) -> Result<(), String> {
    let started = Instant::now();
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_nodelay(true).ok();

    let mut accepted = noise::server_accept(stream, key).map_err(|e| e.to_string())?;
    let raw = accepted.channel.recv().map_err(|e| e.to_string())?;
    if raw.len() > MAX_REQUEST {
        return Err("request too large".into());
    }

    let request: Request = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if request.version() != VERSION {
        return respond(&mut accepted.channel, Response::denied(), started);
    }

    let response = match (accepted.pattern, request) {
        (PATTERN_ENROLL, Request::Enroll {
            token,
            static_pub,
            device_id,
            label,
            ..
        }) => handle_enroll(store, &token, &static_pub, &device_id, &label),

        (PATTERN_EVAL, Request::Eval { blinded, .. }) => match accepted.client_static {
            Some(static_pub) => handle_eval(store, rates, &static_pub, &blinded),
            None => Response::denied(),
        },

        _ => Response::denied(),
    };

    respond(&mut accepted.channel, response, started)
}

pub fn handle_enroll(
    store: &db::Db,
    token: &str,
    static_pub_b64: &str,
    device_id_hex: &str,
    label: &str,
) -> Response {
    let Ok(pub_bytes) = B64.decode(static_pub_b64) else {
        return Response::denied();
    };
    let Ok(static_pub) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
        return Response::denied();
    };
    let Ok(device_id) = hex::decode(device_id_hex) else {
        return Response::denied();
    };

    let outcome = store.with(|conn| Ok(enroll::handle(conn, token, &static_pub, &device_id, label)));

    match outcome {
        Ok(Ok((resp, enrolled))) => {
            log::request(&hex::encode(&enrolled.device_id), "enrolled", None, None);
            log::info(&format!("enrollment token consumed for {}", enrolled.label));
            alert::enrolled(&hex::encode(&enrolled.device_id), &enrolled.label);
            resp
        }
        _ => {
            log::request("-", "denied", None, None);
            Response::denied()
        }
    }
}

pub fn handle_eval(
    store: &db::Db,
    rates: &alert::Rates,
    static_pub: &[u8; 32],
    blinded_b64: &str,
) -> Response {
    let Ok(bytes) = B64.decode(blinded_b64) else {
        return Response::denied();
    };
    let Ok(blinded) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return Response::denied();
    };

    let now = db::now();
    let grant = match store.with(|conn| budget::consume(conn, static_pub, now)) {
        Ok(g) => g,
        Err(e) => {
            log::error(&format!("budget: {e}"));
            log::request("-", "error", None, None);
            return Response::denied();
        }
    };

    match grant {
        budget::Grant::Allowed {
            device_id,
            key,
            tokens_left,
            lifetime,
        } => {
            let device = hex::encode(&device_id);
            match bw_proto::oprf::evaluate(&key, &blinded) {
                Ok(evaluated) => {
                    log::request(&device, "ok", Some(tokens_left), Some(lifetime));
                    alert::check(&device, lifetime);
                    rates.record(&device, now);
                    Response::ok(B64.encode(evaluated), tokens_left.floor() as u32)
                }
                Err(e) => {
                    log::error(&format!("evaluate: {e}"));
                    log::request(&device, "bad-element", Some(tokens_left), Some(lifetime));
                    Response::denied()
                }
            }
        }
        budget::Grant::Throttled {
            device_id,
            retry_after_s,
            tokens_left,
            lifetime,
        } => {
            log::request(
                &hex::encode(&device_id),
                "throttled",
                Some(tokens_left),
                Some(lifetime),
            );
            Response::throttled(retry_after_s)
        }
        budget::Grant::Denied { device_id } => {
            let device = device_id.map(hex::encode).unwrap_or_else(|| "-".into());
            log::request(&device, "denied", None, None);
            alert::denied(&device);
            Response::denied()
        }
    }
}

pub fn respond<S: Read + Write>(
    channel: &mut noise::Channel<S>,
    response: Response,
    started: Instant,
) -> Result<(), String> {
    if matches!(response, Response::Denied { .. }) {
        if let Some(remaining) = DENIED_FLOOR.checked_sub(started.elapsed()) {
            std::thread::sleep(remaining);
        }
    }
    let body = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    channel.send(&body).map_err(|e| e.to_string())
}
