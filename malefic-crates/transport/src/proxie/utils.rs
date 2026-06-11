use crate::proxie::{
    proxy::{Auth, HTTPProxy, SOCKS5Command},
    target::{Target, TargetHost, ToTarget},
};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};

pub(crate) fn make_http_connect_request(addr: &impl ToTarget, proxy: &HTTPProxy) -> Result<String> {
    let addr = addr.to_target()?.to_string();
    let mut request = format!(
        "CONNECT {0} HTTP/1.1\r\n\
        Host: {0}\r\n\
        User-Agent: proxie/0.0\r\n\
        Proxy-Connection: Keep-Alive\r\n",
        addr
    );
    if let Some(auth) = &proxy.auth {
        let raw_auth = format!("{}:{}", auth.username, auth.password);
        let encoded_auth: String = general_purpose::STANDARD.encode(raw_auth.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded_auth));
    }
    request.push_str("\r\n");
    Ok(request)
}

pub(crate) fn make_socks5_initial_request(auth: &Option<Auth>) -> Vec<u8> {
    let mut request = vec![0x05];
    match auth {
        Some(_) => {
            request.push(2u8);
            request.push(0x00);
            request.push(0x02);
        }
        None => {
            request.push(1u8);
            request.push(0x00);
        }
    }
    request
}

pub(crate) fn make_socks5_authentication_request(auth: &Auth) -> Vec<u8> {
    let mut request = vec![0x01];
    request.push(auth.username.len() as u8);
    for c in auth.username.chars() {
        request.push(c as u8);
    }
    request.push(auth.password.len() as u8);
    for c in auth.password.chars() {
        request.push(c as u8);
    }
    request
}

pub(crate) fn make_socks5_request(cmd: SOCKS5Command, target: &Target) -> Result<Vec<u8>> {
    let mut request = vec![0x05];
    let cmd = match cmd {
        SOCKS5Command::CONNECT => 0x01,
    };
    request.push(cmd);
    request.push(0x00);
    match &target.host {
        TargetHost::IPv4(ip) => {
            request.push(0x01);
            for byte in ip.octets() {
                request.push(byte);
            }
        }
        TargetHost::IPv6(ip) => {
            request.push(0x04);
            for byte in ip.octets() {
                request.push(byte);
            }
        }
        TargetHost::Hostname(host) => {
            request.push(0x03);
            request.push(host.len() as u8);
            for c in host.chars() {
                request.push(c as u8);
            }
        }
    };
    request.push((target.port >> 8) as u8);
    request.push((target.port & 0x00FF) as u8);
    Ok(request)
}
