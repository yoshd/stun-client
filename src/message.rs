//! This module implements some of the STUN protocol message processing based on RFC 8489 and RFC 5780.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::{thread_rng, Rng};

use super::error::*;

/// Magic cookie
pub const MAGIC_COOKIE: u32 = 0x2112A442;

// Methods
/// Binding method
pub const METHOD_BINDING: u16 = 0x0001;

// Classes
/// A constant that represents a class request
pub const CLASS_REQUEST: u16 = 0x0000;
/// A constant that represents a class indication
pub const CLASS_INDICATION: u16 = 0x0010;
/// A constant that represents a class success response
pub const CLASS_SUCCESS_RESPONSE: u16 = 0x0100;
/// A constant that represents a class error response
pub const CLASS_ERROR_RESPONSE: u16 = 0x0110;

/// STUN header size
pub const HEADER_BYTE_SIZE: usize = 20;

// STUN Attributes
/// MAPPED-ADDRESS attribute
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// XOR-MAPPED-ADDRESS attribute
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// ERROR-CODE attribute
pub const ATTR_ERROR_CODE: u16 = 0x0009;
/// SOFTWARE attribute
pub const ATTR_SOFTWARE: u16 = 0x8022;

// RFC 5780 NAT Behavior Discovery
/// OTHER-ADDRESS attribute
pub const ATTR_OTHER_ADDRESS: u16 = 0x802c;
/// CHANGE-REQUEST attribute
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;
/// RESPONSE-ORIGIN attribute
pub const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;

/// The "change IP" flag for the CHANGE-REQUEST attribute.
pub const CHANGE_REQUEST_IP_FLAG: u32 = 0x00000004;
/// The "change port" flag for the CHANGE-REQUEST attribute.
pub const CHANGE_REQUEST_PORT_FLAG: u32 = 0x00000002;

pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;

/// Enum representing STUN method
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    Binding,
    Unknown(u16),
}

impl Method {
    /// Convert from u16 to Method.
    pub fn from_u16(method: u16) -> Self {
        match method {
            METHOD_BINDING => Self::Binding,
            _ => Self::Unknown(method),
        }
    }

    /// Convert from Method to u16.
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Binding => METHOD_BINDING,
            Self::Unknown(method) => method.clone(),
        }
    }
}

/// Enum representing STUN class
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Class {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
    Unknown(u16),
}

impl Class {
    /// Convert from u16 to Class.
    pub fn from_u16(class: u16) -> Self {
        match class {
            CLASS_REQUEST => Self::Request,
            CLASS_INDICATION => Self::Indication,
            CLASS_SUCCESS_RESPONSE => Self::SuccessResponse,
            CLASS_ERROR_RESPONSE => Self::ErrorResponse,
            _ => Self::Unknown(class),
        }
    }

    /// Convert from u16 to Class.
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

/// Enum representing STUN attribute
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Attribute {
    MappedAddress,
    XORMappedAddress,
    Software,
    OtherAddress,
    ChangeRequest,
    ResponseOrigin,
    ErrorCode,
    Unknown(u16),
}

impl Attribute {
    /// Convert from u16 to Attribute.
    pub fn from_u16(attribute: u16) -> Self {
        match attribute {
            ATTR_MAPPED_ADDRESS => Self::MappedAddress,
            ATTR_XOR_MAPPED_ADDRESS => Self::XORMappedAddress,
            ATTR_SOFTWARE => Self::Software,
            ATTR_OTHER_ADDRESS => Self::OtherAddress,
            ATTR_CHANGE_REQUEST => Self::ChangeRequest,
            ATTR_RESPONSE_ORIGIN => Self::ResponseOrigin,
            ATTR_ERROR_CODE => Self::ErrorCode,
            _ => Self::Unknown(attribute),
        }
    }

    /// Convert from u16 to Attribute.
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::MappedAddress => ATTR_MAPPED_ADDRESS,
            Self::XORMappedAddress => ATTR_XOR_MAPPED_ADDRESS,
            Self::Software => ATTR_SOFTWARE,
            Self::OtherAddress => ATTR_OTHER_ADDRESS,
            Self::ChangeRequest => ATTR_CHANGE_REQUEST,
            Self::ResponseOrigin => ATTR_RESPONSE_ORIGIN,
            Self::ErrorCode => ATTR_ERROR_CODE,
            Self::Unknown(attribute) => attribute.clone(),
        }
    }

    /// Gets the value of the MAPPED-ADDRESS attribute from Message.
    pub fn get_mapped_address(message: &Message) -> Option<SocketAddr> {
        Self::decode_simple_address_attribute(message, Self::MappedAddress)
    }

    /// Gets the value of the XOR-MAPPED-ADDRESS attribute from Message.
    pub fn get_xor_mapped_address(message: &Message) -> Option<SocketAddr> {
        let attr_value = message.get_raw_attr_value(Self::XORMappedAddress)?;
        let family = attr_value[1];
        // RFC8489: X-Port is computed by XOR'ing the mapped port with the most significant 16 bits of the magic cookie.
        let mc_bytes = MAGIC_COOKIE.to_be_bytes();
        let port = u16::from_be_bytes([attr_value[2], attr_value[3]])
            ^ u16::from_be_bytes([mc_bytes[0], mc_bytes[1]]);
        match family {
            FAMILY_IPV4 => {
                // RFC8489: If the IP address family is IPv4, X-Address is computed by XOR'ing the mapped IP address with the magic cookie.
                let encoded_ip = &attr_value[4..];
                let b: Vec<u8> = encoded_ip
                    .iter()
                    .zip(&MAGIC_COOKIE.to_be_bytes())
                    .map(|(b, m)| b ^ m)
                    .collect();
                let ip_addr = bytes_to_ip_addr(family, b)?;
                Some(SocketAddr::new(ip_addr, port))
            }
            FAMILY_IPV6 => {
                // RFC8489: If the IP address family is IPv6, X-Address is computed by XOR'ing the mapped IP address with the concatenation of the magic cookie and the 96-bit transaction ID.
                let encoded_ip = &attr_value[4..];
                let mut mc_ti: Vec<u8> = vec![];
                mc_ti.extend(&MAGIC_COOKIE.to_be_bytes());
                mc_ti.extend(&message.header.transaction_id);
                let b: Vec<u8> = encoded_ip.iter().zip(&mc_ti).map(|(b, m)| b ^ m).collect();
                let ip_addr = bytes_to_ip_addr(family, b)?;
                Some(SocketAddr::new(ip_addr, port))
            }
            _ => None,
        }
    }

    /// Gets the value of the SOFTWARE attribute from message.
    pub fn get_software(message: &Message) -> Option<String> {
        let attr_value = message.get_raw_attr_value(Self::Software)?;
        String::from_utf8(attr_value).ok()
    }

    /// Gets the value of the ERROR-CODE attribute from Message.
    pub fn get_error_code(message: &Message) -> Option<ErrorCode> {
        let attr_value = message.get_raw_attr_value(Self::ErrorCode)?;
        let class = (attr_value[2] as u16) * 100;
        let number = attr_value[3] as u16;
        let code = class + number;
        let reason = String::from_utf8(attr_value[4..].to_vec())
            .unwrap_or(String::from("cannot parse error reason"));
        Some(ErrorCode::from(code, reason))
    }

    /// Gets the value of the OTHER-ADDRESS attribute from Message.
    pub fn get_other_address(message: &Message) -> Option<SocketAddr> {
        // RFC5780: it is simply a new name with the same semantics as CHANGED-ADDRESS.
        // RCF3489: Its syntax is identical to MAPPED-ADDRESS.
        Self::decode_simple_address_attribute(message, Self::OtherAddress)
    }

    /// Gets the value of the RESPONSE-ORIGIN attribute from Message.
    pub fn get_response_origin(message: &Message) -> Option<SocketAddr> {
        Self::decode_simple_address_attribute(message, Self::ResponseOrigin)
    }

    /// Generates a value for the CHANGE-REQUEST attribute.
    pub fn generate_change_request_value(change_ip: bool, change_port: bool) -> Vec<u8> {
        let mut value: u32 = 0;
        if change_ip {
            value |= CHANGE_REQUEST_IP_FLAG;
        }

        if change_port {
            value |= CHANGE_REQUEST_PORT_FLAG;
        }

        value.to_be_bytes().to_vec()
    }

    pub fn decode_simple_address_attribute(message: &Message, attr: Self) -> Option<SocketAddr> {
        let attr_value = message.get_raw_attr_value(attr)?;
        let family = attr_value[1];
        let port = u16::from_be_bytes([attr_value[2], attr_value[3]]);
        let ip_addr = bytes_to_ip_addr(family, attr_value[4..].to_vec())?;
        Some(SocketAddr::new(ip_addr, port))
    }
}

/// Struct representing STUN message
#[derive(Debug, Eq, PartialEq)]
pub struct Message {
    header: Header,
    attributes: Option<HashMap<Attribute, Vec<u8>>>,
}

impl Message {
    /// Create a STUN Message.
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

        let transaction_id: Vec<u8> = thread_rng().gen::<[u8; 12]>().to_vec();

        Message {
            header: Header::new(method, class, length, transaction_id),
            attributes: attributes,
        }
    }

    /// Create a STUN message from raw bytes.
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

    /// Converts a Message to a STUN protocol message raw bytes.
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

    /// Get the method from Message.
    pub fn get_method(&self) -> Method {
        self.header.method
    }

    /// Get the class from Message.
    pub fn get_class(&self) -> Class {
        self.header.class
    }

    /// Get the raw attribute bytes from Message.
    pub fn get_raw_attr_value(&self, attr: Attribute) -> Option<Vec<u8>> {
        self.attributes
            .as_ref()?
            .get(&attr)
            .and_then(|v| Some(v.clone()))
    }

    /// Get the transaction id from Message.
    pub fn get_transaction_id(&self) -> Vec<u8> {
        self.header.transaction_id.clone()
    }

    fn decode_attrs(attrs_buf: &[u8]) -> Result<HashMap<Attribute, Vec<u8>>, STUNClientError> {
        let mut attrs_buf = attrs_buf.to_vec();
        let mut attributes = HashMap::new();

        if attrs_buf.is_empty() {
            return Err(STUNClientError::ParseError());
        }

        while !attrs_buf.is_empty() {
            if attrs_buf.len() < 4 {
                return Err(STUNClientError::ParseError());
            }

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

/// Struct representing STUN header
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    method: Method,
    class: Class,
    length: u16,
    transaction_id: Vec<u8>,
}

impl Header {
    /// Create a STUN header.
    pub fn new(method: Method, class: Class, length: u16, transaction_id: Vec<u8>) -> Header {
        Header {
            class: class,
            method: method,
            length: length,
            transaction_id: transaction_id,
        }
    }

    /// Create a STUN header from raw bytes.
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
            // 0..3 is Magic Cookie
            transaction_id: buf[4..].to_vec(),
        })
    }

    /// Converts a Header to a STUN protocol header raw bytes.
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
        Method::from_u16(message_type & 0x3EEF)
    }

    fn decode_class(message_type: u16) -> Class {
        // RFC8489: C1 and C0 represent a 2-bit encoding of the class
        Class::from_u16(message_type & 0x0110)
    }
}

fn bytes_to_ip_addr(family: u8, b: Vec<u8>) -> Option<IpAddr> {
    match family {
        FAMILY_IPV4 => Some(IpAddr::V4(Ipv4Addr::from([b[0], b[1], b[2], b[3]]))),
        FAMILY_IPV6 => Some(IpAddr::V6(Ipv6Addr::from([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15],
        ]))),
        _ => None,
    }
}

/// An enum that defines the type of STUN error code.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCode {
    TryAlternate(String),
    BadRequest(String),
    Unauthorized(String),
    UnknownAttribute(String),
    StaleNonce(String),
    ServerError(String),
    Unknown(String),
}

impl ErrorCode {
    pub fn from(code: u16, reason: String) -> Self {
        match code {
            300 => Self::TryAlternate(reason),
            400 => Self::BadRequest(reason),
            401 => Self::Unauthorized(reason),
            420 => Self::UnknownAttribute(reason),
            438 => Self::StaleNonce(reason),
            500 => Self::ServerError(reason),
            _ => Self::Unknown(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_new_and_message_from_raw_are_equivalent() {
        let mut attrs = HashMap::new();
        attrs.insert(
            Attribute::ChangeRequest,
            Attribute::generate_change_request_value(true, false),
        );
        let msg = Message::new(Method::Binding, Class::Request, Some(attrs));
        let re_built_msg = Message::from_raw(&msg.to_raw()).unwrap();
        assert_eq!(msg, re_built_msg);
    }
}
