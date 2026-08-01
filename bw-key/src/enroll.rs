
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use bw_proto::msg::Response;
use bw_proto::token;

use crate::db::{self, STATE_ACTIVE, STATE_PENDING};

pub struct Enrolled {
    pub device_id: Vec<u8>,
    pub label: String,
}

pub fn handle(
    conn: &mut rusqlite::Connection,
    token_str: &str,
    static_pub: &[u8; 32],
    device_id: &[u8],
    label: &str,
) -> Result<(Response, Enrolled), ()> {
    if device_id.len() != 16 {
        return Err(());
    }
    let parsed = token::Token::decode(token_str).map_err(|_| ())?;
    let hash = parsed.hash();
    let now = db::now();

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ())?;

    let pending: Option<(Vec<u8>, i64, String)> = tx
        .query_row(
            "SELECT device_id, enroll_exp, COALESCE(label, '')
             FROM devices WHERE enroll_hash = ?1 AND state = ?2",
            params![hash.as_slice(), STATE_PENDING],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| ())?;

    let (placeholder_id, exp, ctl_label) = pending.ok_or(())?;
    if exp <= now {
        return Err(());
    }

    if device_id != placeholder_id.as_slice() {
        let taken: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM devices WHERE device_id = ?1",
                [device_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| ())?;
        if taken.is_some() {
            return Err(());
        }
    }

    let oprf_key = bw_proto::oprf::generate_key();
    let label = if label.is_empty() {
        ctl_label
    } else {
        label.to_string()
    };

    tx.execute(
        "UPDATE devices
            SET device_id   = ?1,
                static_pub  = ?2,
                oprf_key    = ?3,
                enroll_hash = NULL,
                enroll_exp  = NULL,
                label       = ?4,
                state       = ?5,
                tokens_ts   = ?6
          WHERE device_id = ?7",
        params![
            device_id,
            static_pub.as_slice(),
            oprf_key.as_slice(),
            label,
            STATE_ACTIVE,
            now,
            placeholder_id
        ],
    )
    .map_err(|_| ())?;

    tx.commit().map_err(|_| ())?;

    Ok((
        Response::enrolled(),
        Enrolled {
            device_id: device_id.to_vec(),
            label,
        },
    ))
}

pub const TOKEN_TTL_SECS: i64 = 900;

pub fn issue_token(
    conn: &mut rusqlite::Connection,
    server_pub: [u8; 32],
    label: &str,
) -> Result<String, String> {
    let tok = token::Token::generate(server_pub);
    let placeholder = bw_proto::rng::bytes::<16>();
    let now = db::now();

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO devices
            (device_id, static_pub, oprf_key, enroll_hash, enroll_exp,
             label, state, tokens, tokens_ts, lifetime, created_at)
         VALUES (?1, NULL, NULL, ?2, ?3, ?4, ?5, 6.0, ?6, 0, ?6)",
        params![
            placeholder.as_slice(),
            tok.hash().as_slice(),
            now + TOKEN_TTL_SECS,
            label,
            STATE_PENDING,
            now
        ],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    Ok(tok.encode())
}
