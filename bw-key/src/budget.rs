
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use crate::db::{self, STATE_ACTIVE};

pub const BUCKET_CAPACITY: f64 = 6.0;
pub const REFILL_SECS: f64 = 1800.0;
pub const LIFETIME_CEILING: i64 = 15_000;

pub enum Grant {
    Allowed {
        device_id: Vec<u8>,
        key: Zeroizing<[u8; 32]>,
        tokens_left: f64,
        lifetime: i64,
    },
    Throttled {
        device_id: Vec<u8>,
        retry_after_s: u64,
        tokens_left: f64,
        lifetime: i64,
    },
    Denied { device_id: Option<Vec<u8>> },
}

pub fn consume(conn: &mut Connection, static_pub: &[u8; 32], now: i64) -> Result<Grant, String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;

    let row: Option<(Vec<u8>, String, Option<Vec<u8>>, f64, i64, i64)> = tx
        .query_row(
            "SELECT device_id, state, oprf_key, tokens, tokens_ts, lifetime
               FROM devices WHERE static_pub = ?1",
            [static_pub.as_slice()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let Some((device_id, state, oprf_key, tokens, tokens_ts, lifetime)) = row else {
        return Ok(Grant::Denied { device_id: None });
    };

    let elapsed = (now - tokens_ts).max(0) as f64;
    let tokens = (tokens + elapsed / REFILL_SECS).min(BUCKET_CAPACITY);

    if state != STATE_ACTIVE {
        return Ok(Grant::Denied {
            device_id: Some(device_id),
        });
    }

    if lifetime >= LIFETIME_CEILING {
        tx.execute(
            "UPDATE devices SET oprf_key = NULL, state = ?1, revoked_at = ?2 WHERE device_id = ?3",
            params![db::STATE_REVOKED, now, device_id],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(Grant::Denied {
            device_id: Some(device_id),
        });
    }

    let Some(key_bytes) = oprf_key else {
        return Ok(Grant::Denied {
            device_id: Some(device_id),
        });
    };

    if tokens < 1.0 {
        tx.execute(
            "UPDATE devices SET tokens = ?1, tokens_ts = ?2 WHERE device_id = ?3",
            params![tokens, now, device_id],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        return Ok(Grant::Throttled {
            device_id,
            retry_after_s: ((1.0 - tokens) * REFILL_SECS).ceil() as u64,
            tokens_left: tokens,
            lifetime,
        });
    }

    let tokens_left = tokens - 1.0;
    let lifetime = lifetime + 1;

    tx.execute(
        "UPDATE devices
            SET tokens = ?1, tokens_ts = ?2, lifetime = ?3, last_seen = ?2
          WHERE device_id = ?4",
        params![tokens_left, now, lifetime, device_id],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    let key = <[u8; 32]>::try_from(key_bytes.as_slice())
        .map_err(|_| "stored oprf_key is not 32 bytes".to_string())?;

    Ok(Grant::Allowed {
        device_id,
        key: Zeroizing::new(key),
        tokens_left,
        lifetime,
    })
}
