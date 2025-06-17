use async_net::TcpStream;
use async_trait::async_trait;
use futures::{AsyncReadExt, AsyncWriteExt};
use futures::io::BufReader;
use anyhow::{anyhow, Result};
use crate::transport::proxie::{
    utils::*,
    error::*,
    target::ToTarget,
    proxy::{SOCKS5Proxy, SOCKS5Command, AsyncProxy, ProxyTcpStream},
};

#[async_trait]
impl AsyncProxy for SOCKS5Proxy {
    async fn connect(&self, addr: impl ToTarget + Send) -> Result<ProxyTcpStream> {
        let mut stream = TcpStream::connect((&*self.server, self.port)).await?;

        let auth_method = self.async_std_connect(&mut stream).await?;

        if auth_method == 0x02 {
            self.async_std_authenticate(&mut stream).await?;
        }

        self.async_std_request(&mut stream, addr).await?;

        Ok(ProxyTcpStream {
            stream
        })
    }
}

impl SOCKS5Proxy {
    async fn async_std_connect(&self, stream: &mut TcpStream) -> Result<u8> {
        let peer = stream.peer_addr()?;

        let request = make_socks5_initial_request(&self.auth);
        stream.write_all(&request).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut buffer = vec![0u8; 2];

        let mut buffer_len = 0;
        while buffer_len < 2 {
            let read = reader.read(&mut buffer[buffer_len..]).await?;
            buffer_len += read;
        }

        if buffer[1] == 0xFF { //NO ACCEPTABLE METHODS
            return Err(anyhow!(Socks5HandshakeError {
                socket: peer,
            }));
        }

        Ok(buffer[1])
    }

    async fn async_std_authenticate(&self, stream: &mut TcpStream) -> Result<()> {
        let peer = stream.peer_addr()?;

        let request = match &self.auth {
            Some(auth) => make_socks5_authentication_request(&auth),
            None => return Err(anyhow!(Socks5HandshakeError {
                socket: peer,
            })),
        };
        stream.write_all(&request).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut buffer = vec![0u8; 2];

        let mut buffer_len = 0;
        while buffer_len < 2 {
            let read = reader.read(&mut buffer[buffer_len..]).await?;
            buffer_len += read;
        }

        if buffer[1] != 0x00 { //Authentication failure
            return Err(anyhow!(Socks5HandshakeError {
                socket: peer,
            }));
        }

        Ok(())
    }

    async fn async_std_request(&self, stream: &mut TcpStream, addr: impl ToTarget) -> Result<()> {
        let target = addr.to_target()?;
        let peer = stream.peer_addr()?;

        let request = make_socks5_request(SOCKS5Command::CONNECT, &target)?;
        stream.write_all(&request).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut buffer = vec![0u8; 512];

        let mut buffer_len = 0;
        while buffer_len < 4 { //Read until ATYPE
            let read = reader.read(&mut buffer[buffer_len..]).await?;
            buffer_len += read;
        }

        if buffer[3] == 0x01 { //IPv4
            while buffer_len < 10 { //Additional 4 bytes for IPv4 and 2 bytes for port
                let read = reader.read(&mut buffer[buffer_len..]).await?;
                buffer_len += read;
            }
        } else if buffer[3] == 0x04 { //IPv6
            while buffer_len < 22 { //Additional 16 bytes for IPv6 and 2 bytes for port
                let read = reader.read(&mut buffer[buffer_len..]).await?;
                buffer_len += read;
            }
        } else if buffer[3] == 0x03 { //Domain name
            while buffer_len < 5 { //Get domain length
                let read = reader.read(&mut buffer[buffer_len..]).await?;
                buffer_len += read;
            }

            while buffer_len < 7 + buffer[4] as usize { //Additional buffer[4] bytes for domain name and 2 bytes for port
                let read = reader.read(&mut buffer[buffer_len..]).await?;
                buffer_len += read;
            }
        } else { //Malformed packet
            return Err(anyhow!(Socks5HandshakeError {
                socket: peer,
            }));
        }

        if buffer[1] != 0x00 { //Request refused
            return Err(anyhow!(Socks5RequestError {
                socket: peer,
                error_type: buffer[1],
            }));
        }

        Ok(())
    }
}