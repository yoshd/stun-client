//! This is a simple async_std based asynchronous STUN client library.
//! At the moment only some features of [RFC8489](https://tools.ietf.org/html/rfc8489) are implemented and only simple binding requests are possible.
//!
//! It also supports the OTHER-ADDRESS and CHANGE-REQUEST attributes for [RFC5780](https://tools.ietf.org/html/rfc5780) -based NAT Behavior Discovery
//!
//! ## Example
//!
//! ```
//! use async_std::task;
//! use stun_client::*;
//!
//! task::block_on(async {
//!     let mut client = Client::new("0.0.0.0:0", None).await.unwrap();
//!     let res = client
//!         .binding_request("stun.l.google.com:19302", None)
//!         .await
//!         .unwrap();
//!     let class = res.get_class();
//!     match class {
//!         Class::SuccessResponse => {
//!             let xor_mapped_addr = Attribute::get_xor_mapped_address(&res);
//!             println!("XOR-MAPPED-ADDRESS: {}", xor_mapped_addr.unwrap());
//!         },
//!         _ => panic!("error"),
//!     }
//! });
//! ```

mod client;
mod error;
mod message;
pub mod nat_behavior_discovery;

pub use client::*;
pub use error::*;
pub use message::*;
