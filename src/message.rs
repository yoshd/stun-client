use std::collections::HashMap;

use super::error::*;

// Magic cookie
pub const MAGIC_COOKIE: u32 = 0x2112A442;

// Methods
pub const METHOD_BINDING: u16 = 0x0001;

// Classes
pub const CLASS_REQUEST: u16 = 0x0000;
pub const CLASS_INDICATION: u16 = 0x0010;
pub const CLASS_SUCCESS_RESPONSE: u16 = 0x0100;
pub const CLASS_ERROR_RESPONSE: u16 = 0x0110;

// STUN Header size
pub const HEADER_BYTE_SIZE: usize = 20;

// STUN Attribute
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// RFC 5780 NAT Behavior Discovery
pub const ATTR_OTHER_ADDRESS: u16 = 0x802c;
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    Binding,
    Unknown(u16),
}

impl Method {
    pub fn from_u16(method: u16) -> Self {
        match method {
            METHOD_BINDING => Self::Binding,
            _ => Self::Unknown(method),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Binding => METHOD_BINDING,
            Self::Unknown(method) => method.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
    Unknown(u16),
}

impl Class {
    pub fn from_u16(class: u16) -> Self {
        match class {
            CLASS_REQUEST => Self::Request,
            CLASS_INDICATION => Self::Indication,
            CLASS_SUCCESS_RESPONSE => Self::SuccessResponse,
            CLASS_ERROR_RESPONSE => Self::ErrorResponse,
            _ => Self::Unknown(class),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Request => CLASS_REQUEST,
            Self::Indication => CLASS_INDICATION,
            Self::SuccessResponse => CLASS_SUCCESS_RESPONSE,
            Self::ErrorResponse => CLASS_ERROR_RESPONSE,
            Self::Unknown(class) => class.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Attribute {
    MappedAddress,
    Username,
    XORMappedAddress,
    OtherAddress,
    ChangeRequest,
    Unknown(u16),
}

impl Attribute {
    pub fn from_u16(attribute: u16) -> Self {
        match attribute {
            ATTR_MAPPED_ADDRESS => Self::MappedAddress,
            ATTR_USERNAME => Self::Username,
            ATTR_XOR_MAPPED_ADDRESS => Self::XORMappedAddress,
            ATTR_OTHER_ADDRESS => Self::OtherAddress,
            ATTR_CHANGE_REQUEST => Self::ChangeRequest,
            _ => Self::Unknown(attribute),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::MappedAddress => ATTR_MAPPED_ADDRESS,
            Self::Username => ATTR_USERNAME,
            Self::XORMappedAddress => ATTR_XOR_MAPPED_ADDRESS,
            Self::OtherAddress => ATTR_OTHER_ADDRESS,
            Self::ChangeRequest => ATTR_CHANGE_REQUEST,
            Self::Unknown(attribute) => attribute.clone(),
        }
    }
}

#[derive(Debug)]
pub struct Message {
    header: Header,
    attributes: Option<HashMap<Attribute, Vec<u8>>>,
}

impl Message {
    pub fn new(
        method: Method,
        class: Class,
        attributes: Option<HashMap<Attribute, Vec<u8>>>,
    ) -> Message {
        let attr_type_byte_size = 2;
        let attr_length_byte_size = 2;
        let length: u16 = if let Some(attributes) = &attributes {
            attributes
                .iter()
                .map(|e| attr_type_byte_size + attr_length_byte_size + e.1.len() as u16)
                .sum()
        } else {
            0
        };

        // Todo: Random
        let transaction_id: Vec<u8> = vec![0; 12];

        Message {
            header: Header::new(method, class, length, transaction_id),
            attributes: attributes,
        }
    }

    pub fn from_raw(buf: &[u8]) -> Result<Message, STUNClientError> {
        if buf.len() < HEADER_BYTE_SIZE {
            return Err(STUNClientError::ParseError());
        }

        let header = Header::from_raw(&buf[..HEADER_BYTE_SIZE])?;
        let mut attrs = None;
        if buf.len() > HEADER_BYTE_SIZE {
            attrs = Some(Message::decode_attrs(&buf[HEADER_BYTE_SIZE..])?);
        }

        Ok(Message {
            header: header,
            attributes: attrs,
        })
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let mut bytes = self.header.to_raw();
        if let Some(attributes) = &self.attributes {
            for (k, v) in attributes.iter() {
                bytes.extend(&k.to_u16().to_be_bytes());
                bytes.extend(&(v.len() as u16).to_be_bytes());
                bytes.extend(v);
            }
        }

        bytes
    }

    pub fn get_method(&self) -> Method {
        self.header.method
    }

    pub fn get_class(&self) -> Class {
        self.header.class
    }

    pub fn decode_attr(&self, attr: Attribute) -> Option<String> {
        let attr_value = self.attributes.as_ref()?.get(&attr)?;
        let result = match attr {
            Attribute::XORMappedAddress => {
                // Todo: IPv6
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

    fn decode_attrs(attrs_buf: &[u8]) -> Result<HashMap<Attribute, Vec<u8>>, STUNClientError> {
        let mut attrs_buf = attrs_buf.to_vec();
        let mut attributes = HashMap::new();

        if attrs_buf.len() < 4 {
            return Err(STUNClientError::ParseError());
        }

        while !attrs_buf.is_empty() {
            let attribute_type = Attribute::from_u16(u16::from_be_bytes([
                attrs_buf.remove(0),
                attrs_buf.remove(0),
            ]));
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

#[derive(Debug)]
pub struct Header {
    method: Method,
    class: Class,
    length: u16,
    transaction_id: Vec<u8>,
}

impl Header {
    pub fn new(method: Method, class: Class, length: u16, transaction_id: Vec<u8>) -> Header {
        Header {
            class: class,
            method: method,
            length: length,
            transaction_id: transaction_id,
        }
    }

    pub fn from_raw(buf: &[u8]) -> Result<Header, STUNClientError> {
        let mut buf = buf.to_vec();
        if buf.len() < HEADER_BYTE_SIZE {
            return Err(STUNClientError::ParseError());
        }

        let message_type = u16::from_be_bytes([buf.remove(0), buf.remove(0)]);
        let class = Header::decode_class(message_type);
        let method = Header::decode_method(message_type);
        let length = u16::from_be_bytes([buf.remove(0), buf.remove(0)]);

        Ok(Header {
            class: class,
            method: method,
            length: length,
            transaction_id: buf,
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

    fn message_type(&self) -> u16 {
        self.class.to_u16() | self.method.to_u16()
    }

    fn decode_method(message_type: u16) -> Method {
        // RFC8489: M11 through M0 represent a 12-bit encoding of the method
        Method::from_u16(message_type & 0x3DDE)
    }

    fn decode_class(message_type: u16) -> Class {
        // RFC8489: C1 and C0 represent a 2-bit encoding of the class
        Class::from_u16(message_type & 0x0110)
    }
}
