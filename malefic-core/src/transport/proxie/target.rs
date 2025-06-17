use std::{
    string::ToString,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use crate::transport::proxie::error::*;

pub(crate) enum TargetHost {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    Hostname(String),
}

pub struct Target {
    pub(crate) host: TargetHost,
    pub(crate) port: u16,
}

impl Target {
    pub(crate) fn new(host: TargetHost, port: u16) -> Self {
        Self {
            host,
            port,
        }
    }
}

impl ToString for Target {
    fn to_string(&self) -> String {
        match &self.host {
            TargetHost::IPv4(host) => format!("{}:{}", host, self.port),
            TargetHost::IPv6(host) => format!("{}:{}", host, self.port),
            TargetHost::Hostname(host) => format!("{}:{}", host, self.port),
        }
    }
}

pub trait ToTarget {
    fn to_target(&self) -> Result<Target, MalformedTargetError>;
}

impl ToTarget for &str {
    fn to_target(&self) -> Result<Target, MalformedTargetError> {
        let colon_pos = match self.find(':') {
            Some(pos) => pos,
            None => return Err(MalformedTargetError),
        };

        let host = &self[0..colon_pos];
        let port_str = &self[colon_pos + 1..];

        let port = match port_str.parse::<u16>() {
            Ok(port) => port,
            Err(_) => return Err(MalformedTargetError),
        };

        let host = if host.starts_with('[') && host.ends_with(']') {
            match host[1..host.len() - 1].parse::<Ipv6Addr>() {
                Ok(ip) => TargetHost::IPv6(ip),
                Err(_) => return Err(MalformedTargetError),
            }
        } else {
            match host.parse::<Ipv4Addr>() {
                Ok(ip) => TargetHost::IPv4(ip),
                Err(_) => {
                    if host.is_empty() || host.ends_with('.') {
                        return Err(MalformedTargetError);
                    }

                    if host.chars().any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-') {
                        return Err(MalformedTargetError);
                    }

                    TargetHost::Hostname(host.into())
                },
            }
        };

        Ok(Target::new(host, port))
    }
}

impl ToTarget for String {
    fn to_target(&self) -> Result<Target, MalformedTargetError> {
        (&**self).to_target()
    }
}

impl ToTarget for &String {
    fn to_target(&self) -> Result<Target, MalformedTargetError> {
        (&**self).to_target()
    }
}

impl ToTarget for SocketAddr {
    fn to_target(&self) -> Result<Target, MalformedTargetError> {
        let host = match self {
            SocketAddr::V4(socket) => TargetHost::IPv4(*socket.ip()),
            SocketAddr::V6(socket) => TargetHost::IPv6(*socket.ip()),
        };
        let port = self.port();

        Ok(Target::new(host, port))
    }
}
