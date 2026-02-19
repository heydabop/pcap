pub mod error;
pub mod packet;
pub mod reader;

pub use error::Error;
pub use packet::Packet;
pub use reader::Reader;

// https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-00.html#name-linktype-registry
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DataLink {
    // Null = 0,
    Ethernet = 1,
    // IEEE802_11 = 105,
}

impl TryFrom<u32> for DataLink {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DataLink::Ethernet),
            _ => Err(Error::UnsupportedLinkLayer(value)),
        }
    }
}

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Transport {
    // Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl TryFrom<u8> for Transport {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            6 => Ok(Transport::Tcp),
            17 => Ok(Transport::Udp),
            _ => Err(Error::UnsupportedTransport(value)),
        }
    }
}

// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Network {
    IPv4,
    IPv6,
}

impl Network {
    pub fn try_from_ethertype(ethertype: &[u8]) -> Result<Self, Error> {
        let two_bytes: [u8; 2] = ethertype.try_into()?;
        match two_bytes {
            [8, 0] => Ok(Network::IPv4),
            [0x86, 0xDD] => Ok(Network::IPv6),
            _ => Err(Error::UnsupportedEtherType([two_bytes[0], two_bytes[1]])),
        }
    }
}
