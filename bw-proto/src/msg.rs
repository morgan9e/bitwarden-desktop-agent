//! §5.2 messages. JSON bodies inside the Noise session.
//!
//! The transport already provides authentication, integrity and replay
//! protection, so nothing here is signed at the application layer.

use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 2;

/// Client → server.
///
/// Note the absence of any `device_id` on `Eval`: identity comes from the
/// authenticated Noise static key. A client-supplied identifier could only
/// create the possibility of a mismatch between claimed and authenticated
/// identity.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    #[serde(rename = "eval")]
    Eval { v: u32, blinded: String },
    #[serde(rename = "enroll")]
    Enroll {
        v: u32,
        token: String,
        static_pub: String,
        device_id: String,
        label: String,
    },
}

/// Server → client.
///
/// `Denied` is returned for revoked devices, unknown static keys and pending
/// enrollments alike, with identical timing. Distinguishing them creates a
/// device-enumeration oracle.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    #[serde(rename = "ok")]
    Ok {
        v: u32,
        evaluated: String,
        tokens_left: u32,
    },
    #[serde(rename = "throttled")]
    Throttled { v: u32, retry_after_s: u64 },
    #[serde(rename = "denied")]
    Denied { v: u32 },
    #[serde(rename = "enrolled")]
    Enrolled { v: u32 },
}

impl Request {
    pub fn eval(blinded: String) -> Self {
        Self::Eval {
            v: VERSION,
            blinded,
        }
    }

    pub fn enroll(token: String, static_pub: String, device_id: String, label: String) -> Self {
        Self::Enroll {
            v: VERSION,
            token,
            static_pub,
            device_id,
            label,
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            Self::Eval { v, .. } | Self::Enroll { v, .. } => *v,
        }
    }
}

impl Response {
    pub fn ok(evaluated: String, tokens_left: u32) -> Self {
        Self::Ok {
            v: VERSION,
            evaluated,
            tokens_left,
        }
    }

    pub fn throttled(retry_after_s: u64) -> Self {
        Self::Throttled {
            v: VERSION,
            retry_after_s,
        }
    }

    pub fn denied() -> Self {
        Self::Denied { v: VERSION }
    }

    pub fn enrolled() -> Self {
        Self::Enrolled { v: VERSION }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shapes_match_the_specification() {
        let eval = serde_json::to_value(Request::eval("QUJD".into())).unwrap();
        assert_eq!(eval["v"], 2);
        assert_eq!(eval["type"], "eval");
        assert_eq!(eval["blinded"], "QUJD");
        assert!(eval.get("device_id").is_none());

        let ok = serde_json::to_value(Response::ok("RUZH".into(), 4)).unwrap();
        assert_eq!(ok["type"], "ok");
        assert_eq!(ok["tokens_left"], 4);

        let t = serde_json::to_value(Response::throttled(1200)).unwrap();
        assert_eq!(t["type"], "throttled");
        assert_eq!(t["retry_after_s"], 1200);

        let d = serde_json::to_value(Response::denied()).unwrap();
        assert_eq!(d, serde_json::json!({"v": 2, "type": "denied"}));
    }
}
