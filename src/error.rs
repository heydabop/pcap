use std::error::Error as StdError;
use std::{array, fmt};
use tokio::io;

#[derive(Debug)]
pub enum Error {
    InvalidHeader,
    UnsupportedPCAPVersion {
        major_version: u16,
        minor_version: u16,
    },
    PacketExceededLength {
        max_length: u32,
        length: u32,
    },
    UnsupportedLinkLayer(u32),
    UnsupportedTransport(u8),
    InvalidPacket(String),
    InvalidIndex(usize, usize),
    UnsupportedEtherType([u8; 2]),
    InvalidIPHeader(String),
    UnsupportedProtocol(u8),
    IO(io::Error),
    TryFromSlice(array::TryFromSliceError),
    EmptyPacket,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            InvalidHeader => write!(f, "magic number not found at start of file"),
            UnsupportedPCAPVersion {
                major_version,
                minor_version,
            } => write!(
                f,
                "library only supports version 2.4, found version {major_version}.{minor_version}",
            ),
            PacketExceededLength { max_length, length } => write!(
                f,
                "packet length of {length} exceeds max global header length of {max_length}",
            ),
            UnsupportedLinkLayer(link_layer_type) => {
                write!(f, "unsupported link layer type {link_layer_type}")
            }
            UnsupportedTransport(transport_protocol) => {
                write!(f, "unsupported transport protocol {transport_protocol}")
            }
            InvalidPacket(s) => write!(f, "invalid packet: {s}"),
            InvalidIndex(i, l) => write!(f, "tried to index byte {i} in a {l} length packet"),
            UnsupportedEtherType(ether_type) => {
                write!(
                    f,
                    "unsupported ethertype [{}, {}]",
                    ether_type[0], ether_type[1]
                )
            }
            InvalidIPHeader(reason) => write!(f, "invalid ip header: {reason}"),
            UnsupportedProtocol(protocol) => write!(f, "unsupported protocol {protocol}"),
            IO(e) => write!(f, "underlying IO error: {e}"),
            TryFromSlice(e) => write!(f, "unable to convert slice to array: {e}"),
            EmptyPacket => write!(f, "packet has no data payload"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IO(e)
    }
}

impl From<array::TryFromSliceError> for Error {
    fn from(e: array::TryFromSliceError) -> Self {
        Error::TryFromSlice(e)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            _ => None,
        }
    }
}
