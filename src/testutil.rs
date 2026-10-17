
use std::collections::VecDeque;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use bw_key::{alert, db, server, state};

use crate::askpass::Prompter;
use crate::enroll::ServerEnrollment;

// The state directory comes from XDG_STATE_HOME, which is process-wide.
static ENV: Mutex<()> = Mutex::new(());

pub struct StateDir {
    dir: PathBuf,
    _env: MutexGuard<'static, ()>,
}

impl StateDir {
    pub fn new(name: &str) -> Self {
        let env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("bw-agent-test-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::env::set_var("XDG_STATE_HOME", &dir);
        bw_proto::paths::ensure_state_dir().unwrap();
        Self { dir, _env: env }
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

pub struct KeyServer {
    pub addr: String,
    dir: PathBuf,
    store: Arc<db::Db>,
    key: [u8; 32],
}

impl KeyServer {
    pub fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bw-agent-test-keyd-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        state::ensure_dir(&dir).unwrap();
        let key = state::load_or_create_key(&dir).unwrap();
        let store = Arc::new(db::Db::open(&dir.join(state::DB_FILE)).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let served = store.clone();
        std::thread::spawn(move || {
            let rates = alert::Rates::new();
            for stream in listener.incoming().flatten() {
                server::handle(stream, &served, &key, &rates).ok();
            }
        });

        Self {
            addr,
            dir,
            store,
            key,
        }
    }

    pub fn enrollment(&self, label: &str) -> ServerEnrollment {
        let server_pub = bw_proto::noise::public_key(&self.key);
        let token = self
            .store
            .with(|c| bw_key::enroll::issue_token(c, server_pub, label))
            .unwrap();
        ServerEnrollment {
            addr: self.addr.clone(),
            token,
        }
    }

    pub fn revoke(&self, device_id: &str) {
        let id = hex::decode(device_id).unwrap();
        self.store.with(|c| db::revoke(c, &id)).unwrap();
    }
}

impl Drop for KeyServer {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// Answers prompts in order, then cancels.
pub fn scripted(answers: &[&str]) -> Prompter {
    let queue: Mutex<VecDeque<String>> =
        Mutex::new(answers.iter().map(|a| a.to_string()).collect());
    Box::new(move |_msg: &str| queue.lock().unwrap().pop_front())
}
