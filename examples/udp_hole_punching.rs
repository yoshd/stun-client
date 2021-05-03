//! This sample is a sample that tries Peer-to-Peer communication with reference to RFC5128.
//! Not all NAT types will succeed.
//! Since Redis is used as a signaling server, please prepare Redis yourself when executing it.
//! Also, since this sample does P2P within the same process, it communicates by hairpinning.
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Error};
use async_macros::join;
use async_std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use async_std::{future, task};
use futures::channel::mpsc;
use futures::stream::StreamExt;
use futures::SinkExt;
use redis::AsyncCommands;

use stun_client::nat_behavior_discovery::*;
use stun_client::*;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: cargo run --example udp_hole_punching -- <STUN Server IP:Port (that supports OTHER-ADDRESS and CHANGE-REQUEST)> <Redis Server IP:Port>");
        panic!("invalid argument");
    }

    let stun_addr = &args[1];
    let redis_addr = &args[2];
    task::block_on(async {
        let p1 = String::from("p1");
        let p2 = String::from("p2");
        let t1 = run(
            p1.clone(),
            p2.clone(),
            redis_addr.clone(),
            stun_addr.clone(),
        );
        let t2 = run(
            p2.clone(),
            p1.clone(),
            redis_addr.clone(),
            stun_addr.clone(),
        );
        join!(t1, t2).await;
    });
    Ok(())
}

async fn run(peer_name: String, opponent_name: String, redis_addr: String, stun_addr: String) {
    let t = task::spawn(async move {
        let peer = Peer::new(String::from(peer_name), redis_addr.to_string()).await;
        let (nmt, nft) = peer.nat_behavior_discovery(stun_addr).await.unwrap();
        println!(
            "{:?}: NAT Mapping Type={:?}, NAT Filtering Type={:?}",
            peer.get_name(),
            nmt.mapping_type,
            nft.filtering_type
        );

        let mut addr_candidates = vec![];
        match nmt.mapping_type {
            NATMappingType::NoNAT | NATMappingType::EndpointIndependent => {
                addr_candidates.push(nmt.test1_xor_mapped_addr.unwrap().to_string());
            }
            NATMappingType::AddressDependent => {
                let mut candidate = nmt.test2_xor_mapped_addr.unwrap().clone();
                // "N+1" technique
                candidate.set_port(candidate.port() + 1);
                addr_candidates.push(candidate.to_string());
            }
            NATMappingType::AddressAndPortDependent => {
                let mut candidate = nmt.test3_xor_mapped_addr.unwrap().clone();
                // // "N+1" technique
                candidate.set_port(candidate.port() + 1);
                addr_candidates.push(candidate.to_string());
            }
            NATMappingType::Unknown => {
                panic!("unknown NAT type");
            }
        }

        let opponent_candidates = peer
            .signalling(String::from(opponent_name), addr_candidates)
            .await
            .unwrap();
        let opponent_peer = peer.hole_punching(opponent_candidates).await.unwrap();
        println!(
            "{}: opponent peer address: {:?}",
            peer.get_name(),
            opponent_peer
        );
        peer.send_message_p2p(opponent_peer).await.unwrap();
    });
    t.await;
}

struct Peer {
    name: String,
    socket: Arc<UdpSocket>,
    redis_client: redis::Client,
}

impl Peer {
    pub async fn new(name: String, redis_addr: String) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let socket = Arc::new(socket);
        let redis_client = redis::Client::open(format!("redis://{}/", redis_addr)).unwrap();
        Peer {
            name: name,
            socket: socket,
            redis_client: redis_client,
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub async fn nat_behavior_discovery<A: ToSocketAddrs>(
        &self,
        stun_addr: A,
    ) -> Result<(NATMappingTypeResult, NATFilteringTypeResult), Error> {
        let mut client = Client::from_socket(self.socket.clone(), None);
        // If the Filtering Type is not executed first, the Mapping Type check will create a temporary NAT entry for OTHER-ADDRESS.
        let result_ft = stun_client::nat_behavior_discovery::check_nat_filtering_behavior(
            &mut client,
            &stun_addr,
        )
        .await?;
        let result_mt = stun_client::nat_behavior_discovery::check_nat_mapping_behavior(
            &mut client,
            &stun_addr,
        )
        .await?;
        Ok((result_mt, result_ft))
    }

    pub async fn signalling(
        &self,
        opponent_peer_channel: String,
        addr_candidates: Vec<String>,
    ) -> Result<Vec<String>, Error> {
        let mut publish_conn = self.redis_client.get_async_connection().await?;
        let mut pubsub_conn = self
            .redis_client
            .get_async_connection()
            .await?
            .into_pubsub();
        pubsub_conn.subscribe(&opponent_peer_channel).await?;
        let mut pubsub_stream = pubsub_conn.on_message();

        loop {
            let result: redis::RedisResult<()> = publish_conn.publish(&self.name, "Ready").await;
            result.unwrap();
            let msg: String = pubsub_stream.next().await.unwrap().get_payload().unwrap();
            let result: redis::RedisResult<()> = publish_conn.publish(&self.name, "Ready").await;
            result.unwrap();
            if msg == "Ready" {
                break;
            }
        }

        for addr in addr_candidates {
            let result: redis::RedisResult<()> = publish_conn.publish(&self.name, addr).await;
            result.unwrap();
        }

        let result: redis::RedisResult<()> = publish_conn.publish(&self.name, "Finish").await;
        result.unwrap();

        let mut opponent_candidates = vec![];
        loop {
            let msg: String = pubsub_stream.next().await.unwrap().get_payload()?;
            if msg == "Finish" {
                break;
            }

            if msg == "Ready" {
                continue;
            }

            opponent_candidates.push(msg)
        }

        Ok(opponent_candidates)
    }

    pub async fn hole_punching(
        &self,
        opponent_candidates: Vec<String>,
    ) -> Result<SocketAddr, Error> {
        let (mut tx, mut rx) = mpsc::channel(1);
        let sock = self.socket.clone();
        task::spawn(async move {
            let mut buf = vec![0u8; 128];
            let (_, peer) = sock.recv_from(&mut buf).await.unwrap();
            tx.send(peer).await.unwrap();
        });

        let running = Arc::new(AtomicBool::new(true));
        let running_task = running.clone();
        let sock = self.socket.clone();
        task::spawn(async move {
            while running_task.load(Ordering::Relaxed) {
                for candidate in &opponent_candidates {
                    sock.send_to("test".as_bytes(), candidate).await.unwrap();
                }
                task::sleep(Duration::from_secs(1)).await;
            }
        });

        let peer = future::timeout(Duration::from_secs(10), rx.next())
            .await
            .map_err(|_| anyhow!("P2P was not established."))?
            .unwrap();
        running.store(false, Ordering::Relaxed);

        Ok(peer)
    }

    pub async fn send_message_p2p(&self, opponent_peer: SocketAddr) -> Result<(), Error> {
        let msg = format!("Hello, I'm {}.", self.name);
        for _ in 0i32..10 {
            self.socket.send_to(msg.as_bytes(), opponent_peer).await?;
            let mut buf = vec![0u8; 128];
            let (n, _) = self.socket.recv_from(&mut buf).await?;
            println!("{}", String::from_utf8(buf[..n].to_vec())?);
            task::sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }
}
