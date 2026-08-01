
use std::net::{TcpListener, TcpStream};

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use bw_key::budget::{self, Grant, BUCKET_CAPACITY, LIFETIME_CEILING, REFILL_SECS};
use bw_key::{alert, db, enroll, server, state};
use bw_proto::msg::{Request, Response};
use bw_proto::noise;

struct Fixture {
    dir: std::path::PathBuf,
    store: db::Db,
    key: [u8; 32],
    identity: [u8; 32],
    device_id: Vec<u8>,
    rates: alert::Rates,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bw-budget-test-{name}"));
        std::fs::remove_dir_all(&dir).ok();
        state::ensure_dir(&dir).unwrap();
        let key = state::load_or_create_key(&dir).unwrap();
        let store = db::Db::open(&dir.join(state::DB_FILE)).unwrap();

        let identity = noise::generate_private_key();
        let static_pub = noise::public_key(&identity);
        let device_id = vec![0xab; 16];

        let token = store
            .with(|c| enroll::issue_token(c, noise::public_key(&key), "test"))
            .unwrap();
        store
            .with(|c| {
                enroll::handle(c, &token, &static_pub, &device_id, "test")
                    .map_err(|_| "enroll failed".to_string())?;
                Ok(())
            })
            .unwrap();

        Self {
            dir,
            store,
            key,
            identity,
            device_id,
            rates: alert::Rates::new(),
        }
    }

    fn static_pub(&self) -> [u8; 32] {
        noise::public_key(&self.identity)
    }

    fn consume(&self, now: i64) -> Grant {
        self.store
            .with(|c| budget::consume(c, &self.static_pub(), now))
            .unwrap()
    }

    fn row(&self) -> db::DeviceRow {
        self.store
            .with(|c| db::list(c))
            .unwrap()
            .into_iter()
            .find(|r| r.device_id == self.device_id)
            .unwrap()
    }

    fn set(&self, sql: &str) {
        self.store
            .with(|c| c.execute(sql, []).map(|_| ()).map_err(|e| e.to_string()))
            .unwrap();
    }

    fn wire_eval(&self, blinded: [u8; 32]) -> Response {
        let server_pub = noise::public_key(&self.key);
        let identity = self.identity;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        let client = std::thread::spawn(move || {
            let stream = TcpStream::connect(addr).unwrap();
            let mut ch = noise::client_eval(stream, &identity, &server_pub).unwrap();
            let req = Request::eval(B64.encode(blinded));
            ch.send(&serde_json::to_vec(&req).unwrap()).unwrap();
            tx.send(serde_json::from_slice::<Response>(&ch.recv().unwrap()).unwrap())
                .unwrap();
        });

        let (conn, _) = listener.accept().unwrap();
        server::handle(conn, &self.store, &self.key, &self.rates).unwrap();
        client.join().unwrap();
        rx.recv().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

const T0: i64 = 1_700_000_000;


#[test]
fn the_seventh_rapid_request_is_throttled() {
    let fx = Fixture::new("seventh");
    for i in 0..BUCKET_CAPACITY as i64 {
        assert!(
            matches!(fx.consume(T0), Grant::Allowed { .. }),
            "request {i} should have been allowed"
        );
    }
    assert!(matches!(fx.consume(T0), Grant::Throttled { .. }));
    assert_eq!(fx.row().lifetime, BUCKET_CAPACITY as i64);
}

#[test]
fn the_bucket_refills_with_elapsed_time_only() {
    let fx = Fixture::new("refill");
    for _ in 0..BUCKET_CAPACITY as i64 {
        fx.consume(T0);
    }
    assert!(matches!(fx.consume(T0), Grant::Throttled { .. }));

    let later = T0 + REFILL_SECS as i64;
    assert!(matches!(fx.consume(later), Grant::Allowed { .. }));
    assert!(matches!(fx.consume(later), Grant::Throttled { .. }));
}

#[test]
fn the_bucket_never_exceeds_capacity() {
    let fx = Fixture::new("capacity");
    let grant = fx.consume(T0 + 365 * 86_400);
    assert!(matches!(grant, Grant::Allowed { .. }));
    assert!((fx.row().tokens - (BUCKET_CAPACITY - 1.0)).abs() < 1e-9);
}

#[test]
fn a_clock_stepped_backwards_does_not_over_refill() {
    let fx = Fixture::new("clock");
    for _ in 0..BUCKET_CAPACITY as i64 {
        fx.consume(T0);
    }
    assert!(matches!(fx.consume(T0 - 10 * 86_400), Grant::Throttled { .. }));
    assert!((fx.row().tokens - 0.0).abs() < 1e-9);
}

#[test]
fn retry_after_reflects_the_time_to_one_token() {
    let fx = Fixture::new("retry-after");
    for _ in 0..BUCKET_CAPACITY as i64 {
        fx.consume(T0);
    }
    let Grant::Throttled { retry_after_s, .. } = fx.consume(T0) else {
        panic!("expected throttled");
    };
    assert_eq!(retry_after_s, REFILL_SECS as u64);
}


#[test]
fn the_attempt_is_committed_before_the_key_is_returned() {
    let fx = Fixture::new("fail-closed");
    assert!(matches!(fx.consume(T0), Grant::Allowed { .. }));

    let reopened = db::Db::open(&fx.dir.join(state::DB_FILE)).unwrap();
    let row = reopened
        .with(|c| db::list(c))
        .unwrap()
        .into_iter()
        .find(|r| r.device_id == fx.device_id)
        .unwrap();
    assert_eq!(row.lifetime, 1);
    assert!((row.tokens - (BUCKET_CAPACITY - 1.0)).abs() < 1e-9);
}


#[test]
fn no_wire_message_increases_tokens_or_lifetime() {
    let fx = Fixture::new("no-client-budget");
    let before = fx.row();

    let (_, blinded) = bw_proto::oprf::blind(b"12345678").unwrap();
    assert!(matches!(fx.wire_eval(blinded), Response::Ok { .. }));
    let after_ok = fx.row();
    assert_eq!(after_ok.lifetime, before.lifetime + 1);
    assert!(after_ok.tokens < before.tokens);

    assert!(matches!(fx.wire_eval([0xff; 32]), Response::Denied { .. }));
    let after_bad = fx.row();
    assert!(after_bad.tokens <= after_ok.tokens);
    assert!(after_bad.lifetime >= after_ok.lifetime);
}

#[test]
fn an_unknown_static_key_is_denied_and_creates_nothing() {
    let fx = Fixture::new("unknown");
    let stranger = noise::public_key(&noise::generate_private_key());
    let grant = fx
        .store
        .with(|c| budget::consume(c, &stranger, T0))
        .unwrap();
    assert!(matches!(grant, Grant::Denied { device_id: None }));
    assert_eq!(fx.store.with(|c| db::list(c)).unwrap().len(), 1);
}


#[test]
fn a_throttled_request_leaves_lifetime_unchanged() {
    let fx = Fixture::new("throttle-lifetime");
    for _ in 0..BUCKET_CAPACITY as i64 {
        fx.consume(T0);
    }
    let before = fx.row().lifetime;

    for _ in 0..50 {
        assert!(matches!(fx.consume(T0), Grant::Throttled { .. }));
    }
    assert_eq!(
        fx.row().lifetime,
        before,
        "throttled attempts must not burn the lifetime ceiling — that turns \
         the backstop into a denial-of-service lever"
    );
}


#[test]
fn crossing_the_lifetime_ceiling_revokes_rather_than_throttles() {
    let fx = Fixture::new("ceiling");
    fx.set(&format!(
        "UPDATE devices SET lifetime = {}",
        LIFETIME_CEILING - 1
    ));

    assert!(matches!(fx.consume(T0), Grant::Allowed { .. }));
    assert_eq!(fx.row().lifetime, LIFETIME_CEILING);

    assert!(matches!(fx.consume(T0), Grant::Denied { .. }));
    let row = fx.row();
    assert_eq!(row.state, db::STATE_REVOKED);
    assert!(row.revoked_at.is_some());

    let key: Option<Vec<u8>> = fx
        .store
        .with(|c| {
            c.query_row("SELECT oprf_key FROM devices", [], |r| r.get(0))
                .map_err(|e| e.to_string())
        })
        .unwrap();
    assert!(key.is_none(), "k_i must be destroyed, not merely flagged");
}

#[test]
fn a_revoked_device_is_denied() {
    let fx = Fixture::new("revoked");
    let id = fx.device_id.clone();
    fx.store.with(|c| db::revoke(c, &id)).unwrap();
    assert!(matches!(fx.consume(T0), Grant::Denied { .. }));
}

#[test]
fn a_pending_device_is_denied() {
    let fx = Fixture::new("pending");
    fx.set(&format!("UPDATE devices SET state = '{}'", db::STATE_PENDING));
    assert!(matches!(fx.consume(T0), Grant::Denied { .. }));
}


#[test]
fn revoked_and_unknown_devices_are_byte_identical() {
    let fx = Fixture::new("oracle-bytes");
    let id = fx.device_id.clone();
    fx.store.with(|c| db::revoke(c, &id)).unwrap();

    let revoked = fx.wire_eval(bw_proto::oprf::blind(b"12345678").unwrap().1);
    let revoked_bytes = serde_json::to_vec(&revoked).unwrap();

    let other = Fixture::new("oracle-bytes-other");
    let unknown = other.wire_eval(bw_proto::oprf::blind(b"12345678").unwrap().1);
    let _ = &unknown;

    let stranger = Fixture::new("oracle-bytes-stranger");
    stranger.set("DELETE FROM devices");
    let unknown = stranger.wire_eval(bw_proto::oprf::blind(b"12345678").unwrap().1);

    assert_eq!(revoked_bytes, serde_json::to_vec(&unknown).unwrap());
    assert!(matches!(revoked, Response::Denied { .. }));
    assert!(matches!(unknown, Response::Denied { .. }));
}

#[test]
fn denied_responses_share_a_timing_floor() {
    let fx = Fixture::new("oracle-timing");
    fx.set("DELETE FROM devices");
    let started = std::time::Instant::now();
    let resp = fx.wire_eval(bw_proto::oprf::blind(b"12345678").unwrap().1);
    assert!(matches!(resp, Response::Denied { .. }));
    assert!(
        started.elapsed() >= server::DENIED_FLOOR,
        "denied responses must be padded to a fixed deadline"
    );
}


#[test]
fn a_granted_evaluation_matches_a_local_computation() {
    let fx = Fixture::new("e2e");
    let (state, blinded) = bw_proto::oprf::blind(b"12345678").unwrap();

    let Response::Ok { evaluated, .. } = fx.wire_eval(blinded) else {
        panic!("expected ok");
    };
    let evaluated = <[u8; 32]>::try_from(B64.decode(evaluated).unwrap().as_slice()).unwrap();
    let output = state.finalize(b"12345678", &evaluated).unwrap();

    let key: Vec<u8> = fx
        .store
        .with(|c| {
            c.query_row("SELECT oprf_key FROM devices", [], |r| r.get(0))
                .map_err(|e| e.to_string())
        })
        .unwrap();
    let key = <[u8; 32]>::try_from(key.as_slice()).unwrap();
    let (state2, blinded2) = bw_proto::oprf::blind(b"12345678").unwrap();
    let expected = state2
        .finalize(b"12345678", &bw_proto::oprf::evaluate(&key, &blinded2).unwrap())
        .unwrap();

    assert_eq!(*output, *expected);
}
