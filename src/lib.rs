pub mod contract;
pub mod responses;
mod error;
mod state;
pub use did_contract::state::{Did, DID_PREFIX};

#[cfg(test)]
mod test;

