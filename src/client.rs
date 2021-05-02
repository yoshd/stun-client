use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use async_std::future;
use async_std::net::{ToSocketAddrs, UdpSocket};

use super::error::*;
use super::message::*;

const DEFAULT_RECV_TIMEOUT_MS: u64 = 3000;

pub struct Client {
    socket: Rc<UdpSocket>,
    recv_timeout_ms: u64,
}

impl Client {
    pub async fn new<A: ToSocketAddrs>(local_bind_addr: A) -> Result<Client, STUNClientError> {
        let socket = UdpSocket::bind(local_bind_addr)
            .await
            .map_err(|e| STUNClientError::IOError(e))?;
        Ok(Client {
            socket: Rc::new(socket),
            recv_timeout_ms: DEFAULT_RECV_TIMEOUT_MS,
        })
    }

    pub fn from_socket(socket: Rc<UdpSocket>) -> Client {
        Client {
            socket: socket,
            recv_timeout_ms: DEFAULT_RECV_TIMEOUT_MS,
        }
    }

    pub fn set_rcv_timeout(&mut self, ms: u64) {
        self.recv_timeout_ms = ms;
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

        let mut buf = vec![0u8; 1280];
        let fut = self.socket.recv_from(&mut buf);
        let (n, _) = future::timeout(Duration::from_millis(self.recv_timeout_ms), fut)
            .await
            .map_err(|_| STUNClientError::TimeoutError())?
            .map_err(|e| STUNClientError::IOError(e))?;

        Message::from_raw(&buf[..n])
    }
}
