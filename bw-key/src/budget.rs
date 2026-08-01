//! §6 budget enforcement.
//!
//! This is the load-bearing component. Everything else is plumbing around it.
//!
//! The server **cannot distinguish a successful unlock from a failed one** — it
//! never sees the user key or the blob. Two consequences follow:
//!
//! 1. The budget cannot reset on success. It refills only with elapsed time or
//!    by operator action.
//! 2. The budget must exceed legitimate usage, since the server counts your
//!    unlocks alongside an attacker's. Your usage sets the attacker's floor
//!    rate. No parameter tuning escapes this; only PIN length does.
//!
//! ## The three invariants
//!
//! These are the entire security argument for this module. A review of this
//! code asks only these questions.
//!
//! 1. **Fail-closed.** Both counters persist, with `fsync`, *before* the
//!    evaluation is performed. A crash, power loss or kill signal must cost an
//!    attempt, never grant one. Do not batch, defer or cache these writes — a
//!    few dozen `fsync` calls per day is nothing, and every optimisation here
//!    silently removes the only thing protecting the PIN.
//! 2. **No client-controlled budget.** The bucket moves only with elapsed time;
//!    `lifetime` moves only forward, or backward via `bw-keyctl reset` from an
//!    operator shell. Nothing arriving on the wire can increase either budget.
//! 3. **Throttled requests do not count.** A request rejected by the bucket must
//!    not increment `lifetime`. Otherwise an attacker who cannot pass the bucket
//!    can still exhaust the ceiling and destroy the device — turning the
//!    backstop into a denial-of-service lever.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use crate::db::{self, STATE_ACTIVE};

/// Token bucket: capacity 6, one token per 1800 s ⇒ 48 guesses/day.
pub const BUCKET_CAPACITY: f64 = 6.0;
pub const REFILL_SECS: f64 = 1800.0;
/// Monotonic ceiling; crossing it auto-revokes the device.
pub const LIFETIME_CEILING: i64 = 15_000;

pub enum Grant {
    /// The attempt was charged and committed. `key` is `k_i`.
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
    /// Revoked, unknown, or pending — the caller must not say which.
    Denied { device_id: Option<Vec<u8>> },
}

/// Charges one attempt against `static_pub`'s budget, committing before the
/// caller is allowed to evaluate anything.
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

    // Clamp: clocks move backwards, and a backwards step must never refill.
    let elapsed = (now - tokens_ts).max(0) as f64;
    let tokens = (tokens + elapsed / REFILL_SECS).min(BUCKET_CAPACITY);

    if state != STATE_ACTIVE {
        return Ok(Grant::Denied {
            device_id: Some(device_id),
        });
    }

    if lifetime >= LIFETIME_CEILING {
        // the backstop fires: destroy k_i rather than merely refusing
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
        // active but keyless should not happen; treat as revoked
        return Ok(Grant::Denied {
            device_id: Some(device_id),
        });
    };

    if tokens < 1.0 {
        // Invariant 3: the bucket moved, `lifetime` did not.
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

    // Invariant 1: commit, and fsync (PRAGMA synchronous = FULL), *before*
    // returning the key the caller will evaluate with.
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
