
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use bw_key::{alert, db, enroll, server, state};
use bw_proto::msg::{Request, Response, VERSION};
use bw_proto::noise;

struct Fixture {
    dir: std::path::PathBuf,
    store: Arc<db::Db>,
    key: [u8; 32],
    rates: alert::Rates,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bw-key-test-{name}"));
        std::fs::remove_dir_all(&dir).ok();
        state::ensure_dir(&dir).unwrap();
        let key = state::load_or_create_key(&dir).unwrap();
        let store = Arc::new(db::Db::open(&dir.join(state::DB_FILE)).unwrap());
        Self {
            dir,
            store,
            key,
            rates: alert::Rates::new(),
        }
    }

    fn server_pub(&self) -> [u8; 32] {
        noise::public_key(&self.key)
    }

    fn issue(&self, label: &str) -> String {
        self.store
            .with(|c| enroll::issue_token(c, self.server_pub(), label))
            .unwrap()
    }

    fn request(&self, send: impl FnOnce(TcpStream) + Send + 'static) -> () {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || send(TcpStream::connect(addr).unwrap()));
        let (conn, _) = listener.accept().unwrap();
        let _ = server::handle(conn, &self.store, &self.key, &self.rates);
        client.join().unwrap();
    }

    fn enroll(&self, token: &str, device_id: &str, static_pub: [u8; 32]) -> Response {
        let server_pub = self.server_pub();
        let token = token.to_string();
        let device_id = device_id.to_string();
        let (tx, rx) = std::sync::mpsc::channel();

        self.request(move |stream| {
            let mut ch = noise::client_enroll(stream, &server_pub).unwrap();
            let req = Request::enroll(
                token,
                B64.encode(static_pub),
                device_id,
                "laptop".to_string(),
            );
            ch.send(&serde_json::to_vec(&req).unwrap()).unwrap();
            let raw = ch.recv().unwrap();
            tx.send(serde_json::from_slice::<Response>(&raw).unwrap())
                .unwrap();
        });
        rx.recv().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn device_id(byte: u8) -> String {
    hex::encode([byte; 16])
}

#[test]
fn a_valid_token_activates_the_device() {
    let fx = Fixture::new("valid");
    let token = fx.issue("laptop");
    let static_pub = noise::public_key(&noise::generate_private_key());

    assert!(matches!(
        fx.enroll(&token, &device_id(1), static_pub),
        Response::Enrolled { v: VERSION }
    ));

    let rows = fx.store.with(|c| db::list(c)).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, db::STATE_ACTIVE);
    assert_eq!(rows[0].device_id, hex::decode(device_id(1)).unwrap());
    assert_eq!(rows[0].tokens, 6.0);
    assert_eq!(rows[0].lifetime, 0);
}

#[test]
fn a_token_is_single_use() {
    let fx = Fixture::new("single-use");
    let token = fx.issue("laptop");
    let a = noise::public_key(&noise::generate_private_key());
    let b = noise::public_key(&noise::generate_private_key());

    assert!(matches!(
        fx.enroll(&token, &device_id(1), a),
        Response::Enrolled { .. }
    ));
    assert!(matches!(
        fx.enroll(&token, &device_id(2), b),
        Response::Denied { .. }
    ));
}

#[test]
fn a_garbage_token_is_denied() {
    let fx = Fixture::new("garbage");
    let static_pub = noise::public_key(&noise::generate_private_key());
    assert!(matches!(
        fx.enroll("AAAAAAAA", &device_id(1), static_pub),
        Response::Denied { .. }
    ));
    assert!(fx.store.with(|c| db::list(c)).unwrap().is_empty());
}

#[test]
fn a_revoked_device_id_can_never_be_reused() {
    let fx = Fixture::new("reuse");
    let first = fx.issue("laptop");
    let a = noise::public_key(&noise::generate_private_key());
    assert!(matches!(
        fx.enroll(&first, &device_id(1), a),
        Response::Enrolled { .. }
    ));

    let id = hex::decode(device_id(1)).unwrap();
    fx.store.with(|c| db::revoke(c, &id)).unwrap();

    let second = fx.issue("laptop-again");
    let b = noise::public_key(&noise::generate_private_key());
    assert!(matches!(
        fx.enroll(&second, &device_id(1), b),
        Response::Denied { .. }
    ));

    let rows = fx.store.with(|c| db::list(c)).unwrap();
    let tomb = rows.iter().find(|r| r.device_id == id).unwrap();
    assert_eq!(tomb.state, db::STATE_REVOKED);
    assert!(tomb.revoked_at.is_some());
}

#[test]
fn an_expired_token_is_denied() {
    let fx = Fixture::new("expired");
    let token = fx.issue("laptop");
    fx.store
        .with(|c| {
            c.execute("UPDATE devices SET enroll_exp = 1", [])
                .map_err(|e| e.to_string())
        })
        .unwrap();

    let static_pub = noise::public_key(&noise::generate_private_key());
    assert!(matches!(
        fx.enroll(&token, &device_id(1), static_pub),
        Response::Denied { .. }
    ));
}

#[test]
fn an_enroll_message_over_the_authenticated_pattern_is_denied() {
    let fx = Fixture::new("pattern");
    let token = fx.issue("laptop");
    let server_pub = fx.server_pub();
    let identity = noise::generate_private_key();
    let (tx, rx) = std::sync::mpsc::channel();

    fx.request(move |stream| {
        let mut ch = noise::client_eval(stream, &identity, &server_pub).unwrap();
        let req = Request::enroll(
            token,
            B64.encode(noise::public_key(&identity)),
            device_id(1),
            "laptop".into(),
        );
        ch.send(&serde_json::to_vec(&req).unwrap()).unwrap();
        tx.send(serde_json::from_slice::<Response>(&ch.recv().unwrap()).unwrap())
            .unwrap();
    });

    assert!(matches!(rx.recv().unwrap(), Response::Denied { .. }));
}
