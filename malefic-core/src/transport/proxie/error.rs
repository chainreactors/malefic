use std::{
    error::Error,
    fmt::{Display, Formatter, Result},
    net::SocketAddr,
};

#[derive(Debug)]
pub struct MalformedTargetError;

impl Display for MalformedTargetError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Malformed target address. Correct ones should be like: \"example.com:80\", \"1.2.3.4:443\", or \"[2001:db8::1]:443\". ")
    }
}

impl Error for MalformedTargetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub struct HTTPNotOKError {
    pub(crate) code: Option<u16>,
}

impl Display for HTTPNotOKError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self.code {
            Some(code) => write!(f, "HTTP proxy server responsed with a non-200 error code: {}. ", code),
            None => write!(f, "HTTP proxy server response invalid. "),
        }
    }
}

impl Error for HTTPNotOKError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct FailedToConnectError {
    pub(crate) socket: SocketAddr,
}

impl Display for FailedToConnectError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Failed to connect to remote host: {}. ", self.socket)
    }
}

impl Error for FailedToConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct Socks5HandshakeError {
    pub(crate) socket: SocketAddr,
}

impl Display for Socks5HandshakeError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Failed to complete handshake with SOCKS 5 server: {}. ", self.socket)
    }
}

impl Error for Socks5HandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

const SOCKS5_REP_ERROR_MESSAGE: [&'static str; 8] = [ //RFC 1928, Chapter 6
    "General SOCKS server failure",
    "Connection not allowed by ruleset",
    "Network unreachable",
    "Host unreachable",
    "Connection refused",
    "TTL expired",
    "Command not supported",
    "Address type not supported",
];

#[derive(Debug)]
pub(crate) struct Socks5RequestError {
    pub(crate) socket: SocketAddr,
    pub(crate) error_type: u8,
}

impl Display for Socks5RequestError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let reason = if self.error_type < 8 {
            SOCKS5_REP_ERROR_MESSAGE[(self.error_type - 1) as usize]
        } else {
            "Unknown error"
        };
        write!(f, "SOCKS 5 server {} refused request. Reason: {}. ", self.socket, reason)
    }
}

impl Error for Socks5RequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}