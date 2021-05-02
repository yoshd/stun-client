use anyhow::{anyhow, Error};
use async_std::task;

use stun_client::*;

fn main() -> Result<(), Error> {
    task::block_on(async {
        stun_binding().await.unwrap();
    });
    Ok(())
}

async fn stun_binding() -> Result<(), Error> {
    let mut client = Client::new("0.0.0.0:0", None).await?;
    let res = client
        .binding_request("stun.l.google.com:19302", None)
        .await?;

    let class = res.get_class();
    match class {
        Class::SuccessResponse => {
            let xor_mapped_addr = Attribute::get_xor_mapped_address(&res);
            println!("XOR-MAPPED-ADDRESS: {}", xor_mapped_addr.unwrap());
            Ok(())
        }
        _ => Err(anyhow!(format!("failed to request. class: {:?}", class))),
    }
}
