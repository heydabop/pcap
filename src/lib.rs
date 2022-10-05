#![allow(dead_code, clippy::missing_errors_doc)]

mod error;

use std::error::Error;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

pub struct Packet {
    epoch_seconds: u32,
    bytes: Vec<u8>,
}

impl Packet {
    #[must_use]
    pub fn epoch_seconds(&self) -> u32 {
        self.epoch_seconds
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct Reader<T: AsyncRead> {
    reverse: bool,
    source: T,
    max_length: u32,
    data_link_type: u32,
}

impl<T: AsyncRead + std::marker::Unpin> Reader<T> {
    async fn parse_global_header(&mut self) -> Result<(), Box<dyn Error>> {
        let mut global_header = [0; 24];
        self.source.read_exact(&mut global_header).await?;

        self.reverse = if global_header[0..4] == [0xa1, 0xb2, 0xc3, 0xd4] {
            false
        } else if global_header[0..4] == [0xd4, 0xc3, 0xb2, 0xa1] {
            true
        } else {
            return Err(Box::new(error::InvalidHeader {}));
        };

        let major_version = u16::from_ne_bytes([global_header[4], global_header[5]]);
        if major_version != 2 {
            return Err(Box::new(error::UnsupportedVersion::new(major_version)));
        }

        self.max_length = u32::from_ne_bytes([
            global_header[16],
            global_header[17],
            global_header[18],
            global_header[19],
        ]);

        self.data_link_type = u32::from_ne_bytes([
            global_header[20],
            global_header[21],
            global_header[22],
            global_header[23],
        ]);

        Ok(())
    }

    pub async fn new(source: T) -> Result<Self, Box<dyn Error>> {
        let mut this = Self {
            source,
            reverse: false,
            max_length: 0,
            data_link_type: 0,
        };

        this.parse_global_header().await?;

        Ok(this)
    }

    pub async fn read_packet(&mut self) -> Result<Packet, Box<dyn Error>> {
        let mut packet_header = [0; 16];
        self.source.read_exact(&mut packet_header).await?;

        let epoch_seconds = u32::from_ne_bytes([
            packet_header[0],
            packet_header[1],
            packet_header[2],
            packet_header[3],
        ]);

        let length = u32::from_ne_bytes([
            packet_header[8],
            packet_header[9],
            packet_header[10],
            packet_header[11],
        ]);

        if length > self.max_length {
            return Err(Box::new(error::PacketExceededLength::new(
                self.max_length,
                length,
            )));
        }

        let mut bytes = vec![0; length as usize];
        self.source.read_exact(&mut bytes).await?;

        Ok(Packet {
            epoch_seconds,
            bytes,
        })
    }

    // strip headers based on link-layer type
    pub fn data<'a>(&self, packet: &'a [u8]) -> Result<&'a [u8], Box<dyn Error>> {
        if self.data_link_type != 1 {
            return Err(Box::new(error::UnsupportedLinkLayer::new(
                self.data_link_type,
            )));
        }

        let ether_type = &packet[12..14];
        match ether_type {
            [8, 0] => data_from_ipv4(&packet[14..packet.len()]),
            [0x86, 0xDD] => data_from_ipv6(&packet[14..packet.len()]),
            _ => Err(Box::new(error::UnsupportedEtherType::new(ether_type))),
        }
    }
}

impl Reader<BufReader<File>> {
    pub async fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let file = File::open(path).await?;
        let source = BufReader::new(file);

        let mut this = Self {
            source,
            reverse: false,
            max_length: 0,
            data_link_type: 0,
        };

        this.parse_global_header().await?;

        Ok(this)
    }
}

fn data_from_ipv4(packet: &[u8]) -> Result<&[u8], Box<dyn Error>> {
    let version = u8::from_be_bytes([packet[0] >> 4]);
    if version != 4 {
        return Err(Box::new(error::InvalidIPHeader::new(format!(
            "Expected version 4, got version {}",
            version
        ))));
    }

    let header_length = (u8::from_be_bytes([packet[0] & 0xf]) * 4) as usize;
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;

    let protocol = u8::from_be_bytes([packet[9]]);
    match protocol {
        6 => Ok(data_from_tcp(&packet[header_length..total_length])),
        _ => Err(Box::new(error::UnsupportedProtocol::new(protocol))),
    }
}

fn data_from_ipv6(packet: &[u8]) -> Result<&[u8], Box<dyn Error>> {
    let version = u8::from_be_bytes([packet[0] >> 4]);
    if version != 4 {
        return Err(Box::new(error::InvalidIPHeader::new(format!(
            "Expected version 6, got version {}",
            version
        ))));
    }

    let length = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    let protocol = u8::from_be_bytes([packet[6]]);
    match protocol {
        6 => Ok(data_from_tcp(&packet[40..length])),
        _ => Err(Box::new(error::UnsupportedProtocol::new(protocol))),
    }
}

fn data_from_tcp(packet: &[u8]) -> &[u8] {
    let data_offset = (u8::from_be_bytes([packet[12] >> 4]) * 4) as usize;

    &packet[data_offset..packet.len()]
}

#[cfg(test)]
mod tests {
    use super::Reader;

    #[tokio::test]
    async fn new_from_reader() {
        let v: Vec<u8> = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
        ];
        Reader::new(v.as_slice()).await.unwrap();
    }

    #[tokio::test]
    async fn read_from_reader() {
        let v: Vec<u8> = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
            0xa4, 0x93, 0xb8, 0x5e, 0xb6, 9, 0x0d, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4,
        ];
        let mut r = Reader::new(v.as_slice()).await.unwrap();
        assert_eq!(r.read_packet().await.unwrap().bytes, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn new_from_file() {
        Reader::from_file("packets.pcap").await.unwrap();
    }

    #[tokio::test]
    async fn data() {
        let v: Vec<u8> = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
        ];
        let reader = Reader::new(v.as_slice()).await.unwrap();
        let p = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x43, 0xdb, 0xb5, 0x00, 0x00, 0x40, 0x06, 0xa0, 0xfd, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x98, 0x77, 0x1e, 0x61, 0x40, 0x4a, 0xf2, 0x2b,
            0xbf, 0xe5, 0xf2, 0x2e, 0x80, 0x18, 0x02, 0x00, 0xfe, 0x37, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0x60, 0xed, 0x00, 0x35, 0x60, 0xed, 0x00, 0x30, 0x0f, 0x00, 0x01, 0x0b,
            0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39, 0x34,
        ];
        let data = reader.data(&p).unwrap();
        let data_test = [
            0x0f, 0x00, 0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39,
            0x34,
        ];
        assert_eq!(data, data_test);

        let p2 = vec![
            0x4c, 0xcc, 0x6a, 0x49, 0x25, 0xd4, 0x48, 0x5b, 0x39, 0x7b, 0x25, 0x19, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x37, 0xe2, 0x04, 0x40, 0x00, 0x80, 0x06, 0x94, 0xd9, 0xc0, 0xa8,
            0x01, 0x8f, 0xc0, 0xa8, 0x01, 0x03, 0xcd, 0x6e, 0x1e, 0x61, 0xc5, 0x33, 0xee, 0x9f,
            0x06, 0x51, 0xff, 0xc4, 0x50, 0x18, 0x20, 0x14, 0x5f, 0x1d, 0x00, 0x00, 0x0f, 0x00,
            0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39, 0x34,
        ];
        let data2 = reader.data(&p2).unwrap();
        let data2_test = [
            0x0f, 0x00, 0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39,
            0x34,
        ];
        assert_eq!(data2, data2_test);
    }
}
