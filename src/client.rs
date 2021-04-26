use std::collections::HashMap;
use std::error::Error;
use std::rc::Rc;

use async_std::net::{ToSocketAddrs, UdpSocket};

use super::message::*;

pub struct Client {
    socket: Rc<UdpSocket>,
}

impl Client {
    // Todo: Error
    pub async fn new() -> Result<Client, Box<dyn Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Client {
            socket: Rc::new(socket),
        })
    }

    pub fn from_socket(socket: Rc<UdpSocket>) -> Client {
        Client { socket: socket }
    }

    // Todo: Error
    pub async fn binding_request<A: ToSocketAddrs>(
        &self,
        stun_addr: A,
        attrs: HashMap<u16, Vec<u8>>,
    ) -> Result<Message, Box<dyn Error>> {
        let msg = Message::new(METHOD_BINDING, CLASS_REQUEST, attrs);
        let raw_msg = msg.to_raw();
        self.socket.send_to(&raw_msg, stun_addr).await?;

        // Todo: buf.length() < n
        let mut buf = vec![0u8; 1024];
        let (n, _) = self.socket.recv_from(&mut buf).await?;

        Ok(Message::from_raw(&buf[..n]))
    }
}
