pub mod account;
pub mod application;
//pub mod client;
//

pub trait Signable {
    fn record_hash(&self) -> [u8; 32];
    fn signature(&self) -> Vec<u8>;
}
