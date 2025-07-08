use async_net::TcpStream;
use async_trait::async_trait;
use futures::{AsyncBufReadExt, AsyncWriteExt};
use futures::io::BufReader;
use anyhow::{anyhow, Result};
use httparse::{Response, EMPTY_HEADER};
use crate::transport::proxie::{
    utils::*,
    target::ToTarget,
    proxy::{HTTPProxy, AsyncProxy, ProxyTcpStream,},
    error::HTTPNotOKError,
};

#[async_trait]
impl AsyncProxy for HTTPProxy {
    async fn connect(&self, addr: impl ToTarget + Send) -> Result<ProxyTcpStream> {
        let request = make_http_connect_request(&addr, &self)?;

        let mut stream = TcpStream::connect((&*self.server, self.port)).await?;
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(&mut stream);
        let mut buffer = String::new();

        loop {
            reader.read_line(&mut buffer).await?;

            if buffer.ends_with("\r\n\r\n") {
                break;
            }
        }

        parse_http_response(&buffer.as_bytes())?;

        Ok(ProxyTcpStream {
            stream
        })
    }
}

pub(crate) fn parse_http_response(buffer: &[u8]) -> anyhow::Result<()> {
    let mut headers = [EMPTY_HEADER; 64];
    let mut response = Response::new(&mut headers);

    response.parse(&buffer)?;

    match response.code {
        Some(code) => {
            if code != 200 {
                return Err(anyhow!(HTTPNotOKError {
                    code: Some(code),
                }));
            }
        },
        None => return Err(anyhow!(HTTPNotOKError {
            code: None,
        })),
    };

    Ok(())
}