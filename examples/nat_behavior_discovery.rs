use std::env;

use anyhow::Error;
use async_std::net::ToSocketAddrs;
use async_std::task;

use stun_client::*;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: cargo run --example nat_behavior_discovery -- <STUN Server IP:Port (that supports OTHER-ADDRESS and CHANGE-REQUEST)>");
        panic!("invalid argument");
    }

    let stun_addr = &args[1];
    task::block_on(async {
        nat_behavior_discovery(stun_addr).await.unwrap();
    });
    Ok(())
}

async fn nat_behavior_discovery<A: ToSocketAddrs>(stun_addr: A) -> Result<(), Error> {
    let client = Client::new("0.0.0.0:0").await?;
    let result =
        stun_client::nat_behavior_discovery::check_nat_mapping_behavior(&client, &stun_addr)
            .await?;
    println!("NAT Mapping Type: {:?}", result.mapping_type);

    let client = Client::new("0.0.0.0:0").await?;
    let result =
        stun_client::nat_behavior_discovery::check_nat_filtering_behavior(&client, &stun_addr)
            .await?;
    println!("NAT Filtering Type: {:?}", result.filtering_type);
    Ok(())
}
