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
