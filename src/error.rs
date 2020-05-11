use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct InvalidHeader {}

impl fmt::Display for InvalidHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Magic number not found at start of file")
    }
}

impl Error for InvalidHeader {}

#[derive(Debug)]
pub struct UnsupportedVersion {
    version: u16,
}

impl UnsupportedVersion {
    pub fn new(version: u16) -> Self {
        Self { version }
    }
}

impl fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Library only supports major version 2, found major version {}",
            self.version
        )
    }
}

impl Error for UnsupportedVersion {}

#[derive(Debug)]
pub struct PacketExceededLength {
    max_length: u32,
    length: u32,
}

impl PacketExceededLength {
    pub fn new(max_length: u32, length: u32) -> Self {
        Self { max_length, length }
    }
}

impl fmt::Display for PacketExceededLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Packet length of {} exceeds max global header length of {}",
            self.length, self.max_length
        )
    }
}

impl Error for PacketExceededLength {}

#[derive(Debug)]
pub struct UnsupportedLinkLayer {
    link_layer_type: u32,
}

impl UnsupportedLinkLayer {
    pub fn new(l: u32) -> Self {
        Self { link_layer_type: l }
    }
}

impl fmt::Display for UnsupportedLinkLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Missing support for link layer type {}",
            self.link_layer_type
        )
    }
}

impl Error for UnsupportedLinkLayer {}

#[derive(Debug)]
pub struct UnsupportedEtherType {
    ether_type: [u8; 2],
}

impl UnsupportedEtherType {
    pub fn new(e: &[u8]) -> Self {
        Self {
            ether_type: [e[0], e[1]],
        }
    }
}

impl fmt::Display for UnsupportedEtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Missing support for EtherType [{}, {}]",
            self.ether_type[0], self.ether_type[1]
        )
    }
}

impl Error for UnsupportedEtherType {}

#[derive(Debug)]
pub struct InvalidIPHeader {
    reason: String,
}

impl InvalidIPHeader {
    pub fn new(reason: String) -> Self {
        Self { reason }
    }
}

impl fmt::Display for InvalidIPHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.reason)
    }
}

impl Error for InvalidIPHeader {}

#[derive(Debug)]
pub struct UnsupportedProtocol {
    protocol: u8,
}

impl UnsupportedProtocol {
    pub fn new(protocol: u8) -> Self {
        Self { protocol }
    }
}

impl fmt::Display for UnsupportedProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Missing support for protocol {}", self.protocol)
    }
}

impl Error for UnsupportedProtocol {}
