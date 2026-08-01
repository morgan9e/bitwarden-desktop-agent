//! `bw-keyd` — the counting party.
//!
//! The server holds one OPRF key per device, meters how often each may be
//! evaluated, and can destroy a key outright. It never learns a PIN, never sees
//! a vault key, and cannot decrypt anything alone.

pub mod alert;
pub mod budget;
pub mod db;
pub mod enroll;
pub mod log;
pub mod server;
pub mod state;
