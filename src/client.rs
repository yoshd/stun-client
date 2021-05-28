//! This module is a thread-safe async-std-based asynchronous STUN client.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_macros::select;
use async_std::future;
use async_std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use async_std::task;
use futures::channel::mpsc;
use futures::stream::StreamExt;
use futures::SinkExt;

use super::error::*;
use super::message::*;

const DEFAULT_RECV_TIMEOUT_MS: u64 = 3000;
const DEFAULT_RECV_BUF_SIZE: usize = 1024;

/// STUN client options.
#[derive(Clone, Debug)]
pub struct Options {
    pub recv_timeout_ms: u64,
    pub recv_buf_size: usize,
}

/// STUN client.
/// The transport protocol is UDP only and only supports simple STUN Binding requests.
pub struct Client {
    socket: Arc<UdpSocket>,
    recv_timeout_ms: u64,
    transactions: Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<Result<Message, STUNClientError>>>>>,
    running: Arc<AtomicBool>,
    stop_tx: mpsc::Sender<bool>,
}

impl Client {
    /// Create a Client.
    pub async fn new<A: ToSocketAddrs>(
        local_bind_addr: A,
        opts: Option<Options>,
    ) -> Result<Client, STUNClientError> {
        let socket = UdpSocket::bind(local_bind_addr)
            .await
            .map_err(|e| STUNClientError::IOError(e))?;
        let socket = Arc::new(socket);
        let transactions = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel(1);
        let recv_timeout_ms = opts
            .clone()
            .map(|o| o.recv_timeout_ms)
            .unwrap_or_else(|| DEFAULT_RECV_TIMEOUT_MS);
        let client = Client {
            socket: socket.clone(),
            recv_timeout_ms: recv_timeout_ms,
            transactions: transactions.clone(),
            running: running.clone(),
            stop_tx: tx,
        };

        let recv_buf_size = opts
            .map(|o| o.recv_buf_size)
            .unwrap_or_else(|| DEFAULT_RECV_BUF_SIZE);
        task::spawn(async move {
            Self::run_message_receiver(socket, recv_buf_size, running, rx, transactions).await
        });
        Ok(client)
    }

    /// Create a Client from async_std::net::UdpSocket.
    pub fn from_socket(socket: Arc<UdpSocket>, opts: Option<Options>) -> Client {
        let transactions = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel(1);
        let recv_timeout_ms = opts
            .clone()
            .map(|o| o.recv_timeout_ms)
            .unwrap_or_else(|| DEFAULT_RECV_TIMEOUT_MS);
        let client = Client {
            socket: socket.clone(),
            recv_timeout_ms: recv_timeout_ms,
            transactions: transactions.clone(),
            running: running.clone(),
            stop_tx: tx,
        };

        let recv_buf_size = opts
            .map(|o| o.recv_buf_size)
            .unwrap_or_else(|| DEFAULT_RECV_BUF_SIZE);
        task::spawn(async move {
            Self::run_message_receiver(socket, recv_buf_size, running, rx, transactions).await
        });
        client
    }

    /// Send STUN Binding request asynchronously.
    pub async fn binding_request<A: ToSocketAddrs>(
        &mut self,
        stun_addr: A,
        attrs: Option<HashMap<Attribute, Vec<u8>>>,
    ) -> Result<Message, STUNClientError> {
        let msg = Message::new(Method::Binding, Class::Request, attrs);
        let (tx, mut rx) = mpsc::channel(1);
        {
            let mut m = self.transactions.lock().unwrap();
            m.insert(msg.get_transaction_id(), tx);
        }
        let raw_msg = msg.to_raw();
        self.socket
            .send_to(&raw_msg, stun_addr)
            .await
            .map_err(|e| STUNClientError::IOError(e))?;

        let fut = rx.next();
        let res = future::timeout(Duration::from_millis(self.recv_timeout_ms), fut)
            .await
            .map_err(|_| STUNClientError::TimeoutError())?
            .ok_or(STUNClientError::Unknown(String::from(
                "Receive stream terminated unintentionally",
            )))?;

        {
            let mut m = self.transactions.lock().unwrap();
            m.remove(&msg.get_transaction_id());
        }

        res
    }

    async fn run_message_receiver(
        socket: Arc<UdpSocket>,
        recv_buf_size: usize,
        running: Arc<AtomicBool>,
        rx: mpsc::Receiver<bool>,
        transactions: Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<Result<Message, STUNClientError>>>>>,
    ) {
        let mut rx = rx;
        while running.load(Ordering::Relaxed) {
            let mut buf = vec![0u8; recv_buf_size];
            let sock_fut = Self::socket_recv(socket.clone(), &mut buf);
            let stop_fut = Self::stop_recv(&mut rx);
            let result = select!(sock_fut, stop_fut).await;

            let socket_recv_result;
            match result {
                Event::Stop(_) => return,
                Event::Socket(ev) => {
                    socket_recv_result = ev;
                }
            }

            let result = socket_recv_result.map_err(|e| STUNClientError::IOError(e));
            match result {
                Ok(result) => {
                    let msg = Message::from_raw(&buf[..result.0]);
                    match msg {
                        Ok(msg) => {
                            let tx: Option<mpsc::Sender<Result<Message, STUNClientError>>>;
                            {
                                // It's a bug if you panic with this unwrap
                                let transactions = transactions.lock().unwrap();
                                tx = transactions
                                    .get(&msg.get_transaction_id())
                                    .map(|v| v.clone());
                            }
                            if let Some(mut tx) = tx {
                                tx.send(Ok(msg)).await.ok();
                            }
                        }
                        Err(e) => {
                            let transactions_unlocked: Option<
                                HashMap<Vec<u8>, mpsc::Sender<Result<Message, STUNClientError>>>,
                            >;
                            {
                                // It's a bug if you panic with this unwrap
                                let t = transactions.lock().unwrap();
                                transactions_unlocked = Some(t.clone());
                            }
                            if let Some(transactions_unlocked) = transactions_unlocked {
                                for (_, transaction) in transactions_unlocked.iter() {
                                    let mut transaction = transaction.clone();
                                    transaction.send(Err(e.clone())).await.ok();
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let transactions_unlocked: Option<
                        HashMap<Vec<u8>, mpsc::Sender<Result<Message, STUNClientError>>>,
                    >;
                    {
                        // It's a bug if you panic with this unwrap
                        let t = transactions.lock().unwrap();
                        transactions_unlocked = Some(t.clone());
                    }
                    if let Some(transactions_unlocked) = transactions_unlocked {
                        for transaction in transactions_unlocked.iter() {
                            let mut transaction = transaction.1.clone();
                            transaction.send(Err(e.clone())).await.ok();
                        }
                    }
                }
            }
        }
    }

    async fn socket_recv(socket: Arc<UdpSocket>, buf: &mut [u8]) -> Event {
        let result = socket.recv_from(buf).await;
        Event::Socket(result)
    }

    async fn stop_recv(rx: &mut mpsc::Receiver<bool>) -> Event {
        Event::Stop(rx.next().await.unwrap_or_else(|| true))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let mut tx = self.stop_tx.clone();
        task::spawn(async move {
            tx.send(true).await.ok();
        });
    }
}

enum Event {
    Socket(Result<(usize, SocketAddr), std::io::Error>),
    Stop(bool),
}
