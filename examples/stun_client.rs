use std::collections::HashMap;
use std::error::Error;

use async_std::net::UdpSocket;
use async_std::task;

use stun_client::message::*;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello world");

    task::block_on(async { stun_binding().await });
    Ok(())
}

async fn stun_binding() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut buf = vec![0u8; 1024];

    let attrs = HashMap::new();
    let msg = Message::new(METHOD_BINDING, CLASS_REQUEST, attrs);
    let raw_msg = msg.to_raw();

    socket.send_to(&raw_msg, "stun.l.google.com:19302").await?;
    let (n, peer) = socket.recv_from(&mut buf).await?;
    println!("STUN Server: {}", peer);

    let res = Message::from_raw(&buf[..n]);
    let xor_mapped_addr = res.decode_attr(ATTR_XOR_MAPPED_ADDRESS);
    println!("XOR-MAPPED-ADDRESS: {}", xor_mapped_addr.unwrap());
    Ok(())
}
