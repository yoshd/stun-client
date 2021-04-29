use std::collections::HashMap;
use std::rc::Rc;

use async_std::net::{ToSocketAddrs, UdpSocket};

use super::error::*;
use super::message::*;

pub struct Client {
    socket: Rc<UdpSocket>,
}

impl Client {
    pub async fn new<A: ToSocketAddrs>(local_bind_addr: A) -> Result<Client, STUNClientError> {
        let socket = UdpSocket::bind(local_bind_addr)
            .await
            .map_err(|e| STUNClientError::IOError(e))?;
        Ok(Client {
            socket: Rc::new(socket),
        })
    }

    pub fn from_socket(socket: Rc<UdpSocket>) -> Client {
        Client { socket: socket }
    }

    pub async fn binding_request<A: ToSocketAddrs>(
        &self,
        stun_addr: A,
        attrs: Option<HashMap<Attribute, Vec<u8>>>,
    ) -> Result<Message, STUNClientError> {
        let msg = Message::new(Method::Binding, Class::Request, attrs);
        let raw_msg = msg.to_raw();
        self.socket
            .send_to(&raw_msg, stun_addr)
            .await
            .map_err(|e| STUNClientError::IOError(e))?;

        let mut buf = vec![0u8; 1024];
        let (n, _) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| STUNClientError::IOError(e))?;

        Message::from_raw(&buf[..n])
    }
}
