use std::collections::HashMap;
use std::error::Error;
use std::rc::Rc;

use async_std::net::UdpSocket;
use async_std::task;

use stun_client::client::*;
use stun_client::message::*;

fn main() -> Result<(), Box<dyn Error>> {
    task::block_on(async { stun_binding().await });
    Ok(())
}

async fn stun_binding() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Rc::new(socket);
    let client = Client::from_socket(socket.clone());
    let attrs = HashMap::new();
    let res = client
        .binding_request("stun.l.google.com:19302", attrs)
        .await?;
    let xor_mapped_addr = res.decode_attr(ATTR_XOR_MAPPED_ADDRESS);
    println!("XOR-MAPPED-ADDRESS: {}", xor_mapped_addr.unwrap());
    Ok(())
}
