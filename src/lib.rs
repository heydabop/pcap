pub mod error;
pub mod packet;
pub mod reader;

use error::Error;

// https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-00.html#name-linktype-registry
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DataLinkType {
    // Null = 0,
    Ethernet = 1,
    // IEEE802_11 = 105,
}

impl TryFrom<u32> for DataLinkType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DataLinkType::Ethernet),
            _ => Err(Error::UnsupportedLinkLayer(value)),
        }
    }
}

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum TransportProtocol {
    // Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl TryFrom<u8> for TransportProtocol {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            6 => Ok(TransportProtocol::Tcp),
            17 => Ok(TransportProtocol::Udp),
            _ => Err(Error::UnsupportedTransport(value)),
        }
    }
}
