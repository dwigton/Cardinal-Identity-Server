pub mod account;
pub mod application;
pub mod client;
pub mod write_scope;
pub mod read_scope;
pub mod write_authorization;
pub mod read_authorization;
pub mod certificate;
use model::certificate::CertData;
use model::certificate::Certificate;
use encryption::hash_by_parts;

pub trait Signable<T: Signed> {
    fn record_hash(&self) -> [u8; 32];
    fn sign(&self, signature: Vec<u8>) -> T;
}

pub trait Signed {
    fn record_hash(&self) -> [u8; 32];
    fn signature(&self) -> Vec<u8>;
}

pub trait Certifiable<T: Certified> {
    fn data(&self) -> CertData;
    fn certify(&self, authorizing_key: Vec<u8>, signature: Vec<u8>) -> T;
}

pub trait Certified: {
    fn certificate(&self) -> Certificate;
    fn data(&self) -> CertData {
        self.certificate().data
    }
}

impl <T: Certified> Signed for T{
    fn record_hash(&self) -> [u8; 32] {
        self.data().hash()
    }

    fn signature(&self) -> Vec<u8> {
        self.certificate().signature()
    }
}

#[derive(Clone)]
pub enum Scope {
    Read {
        application: String, 
        grant: String
    },
    Write { 
        application: String, 
        grant: String
    },
}

impl Scope {
    pub fn hash(&self) -> [u8; 32] {

        use self::Scope::*;

        match self {
            Read{application, grant} => {
                hash_by_parts (&[
                    b"read",
                    application.as_bytes(),
                    grant.as_bytes(),
                ])
            },
            Write{application, grant} => {
                hash_by_parts (&[
                    b"write",
                    application.as_bytes(),
                    grant.as_bytes(),
                ])
            },
        }
    }
}
