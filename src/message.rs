use std::collections::HashMap;

use super::error::*;

// Magic cookie
pub const MAGIC_COOKIE: u32 = 0x2112A442;

// Methods
pub const METHOD_BINDING: u16 = 0x0001;

// Classes
pub const CLASS_REQUEST: u16 = 0x0000;

// STUN Header size
pub const HEADER_BYTE_SIZE: usize = 20;

// STUN Attribute
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// RFC 5780 NAT Behavior Discovery
pub const ATTR_OTHER_ADDRESS: u16 = 0x802c;
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;

#[derive(Debug)]
pub struct Message {
    class: u16,
    method: u16,
    length: u16,
    transaction_id: [u8; 12],
    // Todo: Option
    attributes: HashMap<u16, Vec<u8>>,
}

impl Message {
    pub fn new(method: u16, class: u16, attributes: HashMap<u16, Vec<u8>>) -> Message {
        let attr_type_byte_size = 2;
        let attr_length_byte_size = 2;
        let length: u16 = attributes
            .iter()
            .map(|e| attr_type_byte_size + attr_length_byte_size + e.1.len() as u16)
            .sum();

        Message {
            class: class,
            method: method,
            length: length,
            attributes: attributes,
            // Todo: Random
            transaction_id: [0; 12],
        }
    }

    pub fn from_raw(buf: &[u8]) -> Result<Message, STUNClientError> {
        // Todo: Header
        let attrs = Message::decode_attrs(&buf[HEADER_BYTE_SIZE..])?;
        Ok(Message {
            // Todo: Header
            class: CLASS_REQUEST,
            method: METHOD_BINDING,
            length: 0,
            attributes: attrs,
            transaction_id: [0; 12],
        })
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let message_type = self.message_type();
        let mut bytes = vec![];
        bytes.extend(&message_type.to_be_bytes());
        bytes.extend(&self.length.to_be_bytes());
        bytes.extend(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend(&self.transaction_id);
        bytes
    }

    pub fn decode_attr(&self, attr: u16) -> Option<String> {
        let attr_value = self.attributes.get(&attr)?;
        let result = match attr {
            ATTR_XOR_MAPPED_ADDRESS => {
                // RFC8489: X-Port is computed by XOR'ing the mapped port with the most significant 16 bits of the magic cookie.
                let mc_bytes = MAGIC_COOKIE.to_be_bytes();
                let port = u16::from_be_bytes([attr_value[2], attr_value[3]])
                    ^ u16::from_be_bytes([mc_bytes[0], mc_bytes[1]]);
                // RFC8489: If the IP address family is IPv4, X-Address is computed by XOR'ing the mapped IP address with the magic cookie.
                let encoded_ip = &attr_value[4..];
                let octets: Vec<u8> = encoded_ip
                    .iter()
                    .zip(&MAGIC_COOKIE.to_be_bytes())
                    .map(|(b, m)| b ^ m)
                    .collect();
                Some(format!(
                    "{}.{}.{}.{}:{}",
                    octets[0], octets[1], octets[2], octets[3], port
                ))
            }
            _ => None,
        };

        result
    }

    fn message_type(&self) -> u16 {
        self.class | self.method
    }

    fn decode_attrs(attrs_buf: &[u8]) -> Result<HashMap<u16, Vec<u8>>, STUNClientError> {
        let mut attrs_buf = attrs_buf.to_vec();
        let mut attributes = HashMap::new();

        if attrs_buf.len() < 4 {
            return Err(STUNClientError::ParseError());
        }

        while !attrs_buf.is_empty() {
            let attribute_type = u16::from_be_bytes([attrs_buf.remove(0), attrs_buf.remove(0)]);
            let length =
                usize::from_be_bytes([0, 0, 0, 0, 0, 0, attrs_buf.remove(0), attrs_buf.remove(0)]);
            if attrs_buf.len() < length {
                return Err(STUNClientError::ParseError());
            }

            let value: Vec<u8> = attrs_buf.drain(..length).collect();
            attributes.insert(attribute_type, value);
        }

        Ok(attributes)
    }
}
