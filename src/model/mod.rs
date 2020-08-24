pub mod account;
pub mod application;
pub mod scope;
pub mod client;

pub trait Signable {
    fn record_hash(&self) -> [u8; 32];
    fn signature(&self) -> Vec<u8>;
}
