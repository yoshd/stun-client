use std::collections::HashMap;
use std::net::IpAddr;

use async_std::net::{SocketAddr, ToSocketAddrs};
use pnet::datalink;
use pnet::ipnetwork::IpNetwork;

use super::client::*;
use super::error::*;
use super::message::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NATMappingType {
    NoNAT,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NATFilteringType {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NATMappingTypeResult {
    pub test1_xor_mapped_addr: Option<SocketAddr>,
    pub test2_xor_mapped_addr: Option<SocketAddr>,
    pub test3_xor_mapped_addr: Option<SocketAddr>,
    pub mapping_type: NATMappingType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NATFilteringTypeResult {
    pub xor_mapped_addr: Option<SocketAddr>,
    pub filtering_type: NATFilteringType,
}

pub async fn check_nat_mapping_behavior<A: ToSocketAddrs>(
    client: &Client,
    stun_addr: A,
) -> Result<NATMappingTypeResult, STUNClientError> {
    let mut result = NATMappingTypeResult {
        test1_xor_mapped_addr: None,
        test2_xor_mapped_addr: None,
        test3_xor_mapped_addr: None,
        mapping_type: NATMappingType::Unknown,
    };

    // get NIC IPs
    let local_ips: Vec<IpNetwork> = datalink::interfaces()
        .iter()
        .flat_map(|i| i.ips.clone())
        .collect();

    // Test1
    // Send a Binding request and check the Endpoint mapped to NAT.
    // Compare with the IP of the NIC and check if it is behind the NAT.
    let t1_res = client.binding_request(&stun_addr, None).await?;
    let other_addr = Attribute::get_other_address(&t1_res).ok_or(
        STUNClientError::NotSupportedError(String::from("OTHER-ADDRESS")),
    )?;
    result.test1_xor_mapped_addr = Some(Attribute::get_xor_mapped_address(&t1_res).ok_or(
        STUNClientError::NotSupportedError(String::from("XOR-MAPPED-ADDRESS")),
    )?);
    match result.test1_xor_mapped_addr.unwrap().ip() {
        IpAddr::V4(addr) => {
            for local_ip in local_ips {
                if let IpNetwork::V4(v4_lip) = local_ip {
                    if v4_lip.ip() == addr {
                        result.mapping_type = NATMappingType::NoNAT;
                        return Ok(result);
                    }
                }
            }
        }
        IpAddr::V6(addr) => {
            for local_ip in local_ips {
                if let IpNetwork::V6(v6_lip) = local_ip {
                    if v6_lip.ip() == addr {
                        result.mapping_type = NATMappingType::NoNAT;
                        return Ok(result);
                    }
                }
            }
            return Err(STUNClientError::ParseError());
        }
    }

    // Test2
    // Send Binding Request to IP:Port of OTHER-ADDRESS.
    // Compare Test1 and Test2 XOR-MAPPED-ADDRESS to check if it is EIM-NAT.
    let t2_res = client.binding_request(&other_addr, None).await?;
    result.test2_xor_mapped_addr = Some(Attribute::get_xor_mapped_address(&t2_res).ok_or(
        STUNClientError::NotSupportedError(String::from("XOR-MAPPED-ADDRESS")),
    )?);
    if result.test1_xor_mapped_addr == result.test2_xor_mapped_addr {
        result.mapping_type = NATMappingType::EndpointIndependent;
        return Ok(result);
    }

    // Test3
    // Send a Binding Request to the IP used in Test1 and the Port used in Test2.
    // (That is, use the primary IP and secondary Port.)
    // Compare Test2 and Test3 XOR-MAPPED-ADDRESS to check if it is ADM-NAT or APDM-NAT.
    // stun_addr is a known value, so it's okay to unwrap it.
    let mut t3_addr = stun_addr.to_socket_addrs().await.unwrap().next().unwrap();
    t3_addr.set_port(other_addr.port());
    let t3_res = client.binding_request(&t3_addr, None).await?;
    result.test3_xor_mapped_addr = Some(Attribute::get_xor_mapped_address(&t3_res).ok_or(
        STUNClientError::NotSupportedError(String::from("XOR-MAPPED-ADDRESS")),
    )?);
    if result.test2_xor_mapped_addr == result.test3_xor_mapped_addr {
        result.mapping_type = NATMappingType::AddressDependent;
        return Ok(result);
    }

    result.mapping_type = NATMappingType::AddressAndPortDependent;
    Ok(result)
}

pub async fn check_nat_filtering_behavior<A: ToSocketAddrs>(
    client: &Client,
    stun_addr: A,
) -> Result<NATFilteringTypeResult, STUNClientError> {
    // Test1
    // Send a Binding request and check the Endpoint mapped to NAT.
    let t1_res = client.binding_request(&stun_addr, None).await?;
    let xor_mapped_addr = Some(Attribute::get_xor_mapped_address(&t1_res).ok_or(
        STUNClientError::NotSupportedError(String::from("XOR-MAPPED-ADDRESS")),
    )?);

    // Test2
    // Send Binding Request with the "change IP" and "change port" flags of CHANGE-REQUEST turned on.
    // As a result, the response is sent from IP:Port which is different from the sent IP:Port.
    // If the response can be received, it is EIF-NAT.
    let mut attrs = HashMap::new();
    let change_request = Attribute::generate_change_request_value(true, true);
    attrs.insert(Attribute::ChangeRequest, change_request);
    let t2_res = client.binding_request(&stun_addr, Some(attrs)).await;
    match t2_res {
        Ok(_) => {
            return Ok(NATFilteringTypeResult {
                xor_mapped_addr: xor_mapped_addr,
                filtering_type: NATFilteringType::EndpointIndependent,
            })
        }
        Err(e) => {
            match e {
                STUNClientError::TimeoutError() => { /* Run Test3 below */ }
                _ => return Err(e),
            }
        }
    }

    // Test3
    // Send a binding request with only the "change port" flag in CHANGE-REQUEST turned on.
    // As a result, the response is sent from Port which is different from the sent Port.(Same IP address)
    // If the response can be received, it is ADF-NAT, and if it cannot be received, it is APDF-NAT.
    let mut attrs = HashMap::new();
    let change_request = Attribute::generate_change_request_value(false, true);
    attrs.insert(Attribute::ChangeRequest, change_request);
    let t3_res = client.binding_request(&stun_addr, Some(attrs)).await;
    match t3_res {
        Ok(_) => {
            return Ok(NATFilteringTypeResult {
                xor_mapped_addr: xor_mapped_addr,
                filtering_type: NATFilteringType::AddressDependent,
            })
        }
        Err(e) => match e {
            STUNClientError::TimeoutError() => {
                return Ok(NATFilteringTypeResult {
                    xor_mapped_addr: xor_mapped_addr,
                    filtering_type: NATFilteringType::AddressAndPortDependent,
                })
            }
            _ => return Err(e),
        },
    }
}
