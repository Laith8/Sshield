use std::net::IpAddr;
use crate::source::event::RawLoginEntry;

pub enum LoginEvent {
    AcceptedLogin(LoginEntry),
    FailedLogin (LoginEntry),
    IgnoredLogin(LoginEntry),
    Unparseable(RawLoginEntry)
}

/// timestamp in microseconds
pub struct LoginEntry {
    message: String,
    user: Option<String>,
    ip: IpAddr,
    port: Option<u16>,
    timestamp: i64,
}