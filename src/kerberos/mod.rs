pub mod asktgs;
pub mod asktgt;
pub mod brute;
pub mod changepw;
pub mod crypto;
pub mod describe;
pub mod forge;
pub mod hash;
pub mod roast;
pub mod s4u;
pub mod tgssub;
pub mod tgtdeleg;
pub mod ticket;

use std::error::Error;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;

pub const KERBEROS_PORT: u16 = 88;
const MAX_KDC_RESPONSE: usize = 10 * 1024 * 1024; // 10 MB cap

fn is_kerberos_response(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let tag = data[0];
    // APPLICATION tags: AS-REP=0x6b, TGS-REP=0x6d, KRB-ERROR=0x7e, AP-REP=0x6f
    matches!(tag, 0x6b | 0x6d | 0x6f | 0x7e | 0x30)
}

pub async fn send_kdc_udp(dc: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let addr: SocketAddr = format!("{}:{}", dc, KERBEROS_PORT).parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(data, addr).await?;
    let mut buf = vec![0u8; 65535];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        socket.recv_from(&mut buf),
    )
    .await??;
    buf.truncate(len);
    Ok(buf)
}

pub async fn send_kdc_tcp(dc: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let addr = format!("{}:{}", dc, KERBEROS_PORT);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await??;

    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_KDC_RESPONSE {
        return Err(format!("KDC response too large: {} bytes", resp_len).into());
    }

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

pub async fn send_kdc(dc: &str, data: &[u8], use_tcp: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    if use_tcp {
        send_kdc_tcp(dc, data).await
    } else {
        match send_kdc_udp(dc, data).await {
            Ok(resp) => {
                if is_kerberos_response(&resp) {
                    Ok(resp)
                } else {
                    send_kdc_tcp(dc, data).await
                }
            }
            Err(_) => send_kdc_tcp(dc, data).await,
        }
    }
}
