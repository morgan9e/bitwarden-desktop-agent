//! Wire protocol and shared client/server pieces for bw-agent v2.
//!
//! Everything both ends of the OPRF exchange must agree on lives here, so that
//! the client and the server cannot silently diverge.

pub mod msg;
pub mod noise;
pub mod oprf;
pub mod paths;
pub mod rng;
pub mod token;
