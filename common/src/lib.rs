mod proto {
    include!(concat!(env!("OUT_DIR"), "/common/mod.rs"));
}

pub mod envelope;
pub mod secure;
pub mod secure_error;
