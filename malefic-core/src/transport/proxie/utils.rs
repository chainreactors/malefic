use base64::{Engine as _, engine::general_purpose};
use anyhow::Result;
use crate::transport::proxie::{
    target::{Target, TargetHost, ToTarget},
    proxy::{Auth, HTTPProxy, SOCKS5Command},
};

pub(crate) fn make_http_connect_request(addr: &impl ToTarget, proxy: &HTTPProxy) -> Result<String> {
    let addr = addr.to_target()?.to_string();
    let mut request = format!(
        "CONNECT {0} HTTP/1.1\r\n\
        Host: {0}\r\n\
        User-Agent: proxie/0.0\r\n\
        Proxy-Connection: Keep-Alive\r\n",
        addr
    );

    match &proxy.auth {
        Some(auth) => {
            let raw_auth = format!("{}:{}", auth.username, auth.password);
            let encoded_auth: String = general_purpose::STANDARD.encode(raw_auth.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded_auth));
        },
        None => {},
    };

    request.push_str("\r\n");

    Ok(request)
}



pub(crate) fn make_socks5_initial_request(auth: &Option<Auth>) -> Vec<u8> {
    //RFC 1928, version identifier/method selection message
    let mut request = vec![];

    request.push(0x05); //VER = 0x05

    match auth {
        Some(_) => {
            request.push(2u8); //NMETHODS = 2
            request.push(0x00); //METHODS = {NO AUTHENTICATION REQUIRED}
            request.push(0x02); //METHODS = {NO AUTHENTICATION REQUIRED, USERNAME/PASSWORD}
        },
        None => {
            request.push(1u8); //NMETHODS = 1
            request.push(0x00); //METHODS = {NO AUTHENTICATION REQUIRED}
        }
    }

    request
}

pub(crate) fn make_socks5_authentication_request(auth: &Auth) -> Vec<u8> {
    //RFC 1929
    let mut request = vec![];

    request.push(0x01); //VER = 0x01

    let u_len = auth.username.len();
    request.push(u_len as u8); //ULEN
    for c in auth.username.chars() {
        request.push(c as u8); //UNAME
    }

    let p_len = auth.password.len();
    request.push(p_len as u8); //PLEN
    for c in auth.password.chars() {
        request.push(c as u8); //PASSWD
    }

    request
}

pub(crate) fn make_socks5_request(cmd: SOCKS5Command, target: &Target) -> Result<Vec<u8>> {
    //RFC 1928
    let mut request = vec![];

    request.push(0x05); //VER = 0x05

    let cmd = match cmd {
        SOCKS5Command::CONNECT => 0x01 //CMD = 0x01,
        //Other commands unimplemented yet
    };
    request.push(cmd);

    request.push(0x00); //RSV = 0x00

    match &target.host {
        TargetHost::IPv4(ip) => {
            request.push(0x01); //ATYP = 0x01, len(IPv4) = 4

            let ip_bytes = ip.octets();
            for byte in ip_bytes {
                request.push(byte); //DST.ADDR
            }
        },
        TargetHost::IPv6(ip) => {
            request.push(0x04); //ATYP = 0x04, len(IPv6) = 16

            let ip_bytes = ip.octets();
            for byte in ip_bytes {
                request.push(byte); //DST.ADDR
            }
        },
        TargetHost::Hostname(host) => {
            request.push(0x03); //ATYP = 0x03

            let len = host.len();
            request.push(len as u8); //DST.ADDR, first byte indicating length

            for c in host.chars() {
                request.push(c as u8); //DST.ADDR, actual data
            }
        },
    };

    request.push((target.port >> 8) as u8); //High 8 bits of port
    request.push((target.port & 0x00FF) as u8); //Low 8 bits of port

    Ok(request)
}