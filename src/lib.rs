mod error;

use error::Error;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

const MICROSECONDS_BIG_ENDIAN: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
const NANOSECONDS_BIG_ENDIAN: [u8; 4] = [0xA1, 0xB2, 0x3C, 0xD4];
const MICROSECONDS_LITTLE_ENDIAN: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];
const NANOSECONDS_LITTLE_ENDIAN: [u8; 4] = [0xD4, 0x3C, 0xB2, 0xA1];

// https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-00.html#name-linktype-registry
#[derive(PartialEq, Eq)]
enum DataLinkType {
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
    source: T,
    max_length: u32,
    data_link_type: DataLinkType,
}

impl<T: AsyncRead + std::marker::Unpin> Reader<T> {
    pub async fn new(source: T) -> Result<Self, Error> {
        Self::from_pcap_header(source).await
    }

    async fn from_pcap_header(mut source: T) -> Result<Self, Error> {
        // https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-00.html#name-file-header
        let mut pcap_header = [0; 24];
        source.read_exact(&mut pcap_header).await?;

        // magic number
        let magic_number = &pcap_header[0..4];
        if magic_number != MICROSECONDS_BIG_ENDIAN
            && magic_number != NANOSECONDS_BIG_ENDIAN
            && magic_number != MICROSECONDS_LITTLE_ENDIAN
            && magic_number != NANOSECONDS_LITTLE_ENDIAN
        {
            return Err(Error::InvalidHeader);
        }

        let major_version = u16::from_ne_bytes([pcap_header[4], pcap_header[5]]);
        let minor_version = u16::from_ne_bytes([pcap_header[6], pcap_header[7]]);
        if major_version != 2 || minor_version != 4 {
            return Err(Error::UnsupportedPCAPVersion {
                major_version,
                minor_version,
            });
        }

        let max_length = u32::from_ne_bytes([
            pcap_header[16],
            pcap_header[17],
            pcap_header[18],
            pcap_header[19],
        ]);

        let data_link_type = DataLinkType::try_from(u32::from_ne_bytes([
            pcap_header[20],
            pcap_header[21],
            pcap_header[22],
            pcap_header[23],
        ]))?;

        Ok(Self {
            source,
            max_length,
            data_link_type,
        })
    }

    pub async fn read_packet(&mut self) -> Result<Packet, Error> {
        // https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-00.html#name-packet-record
        let mut packet_header = [0; 16];
        self.source.read_exact(&mut packet_header).await?;

        let epoch_seconds = {
            u32::from_ne_bytes([
                packet_header[0],
                packet_header[1],
                packet_header[2],
                packet_header[3],
            ])
        };

        let length = u32::from_ne_bytes([
            packet_header[8],
            packet_header[9],
            packet_header[10],
            packet_header[11],
        ]);

        if length > self.max_length {
            return Err(Error::PacketExceededLength {
                max_length: self.max_length,
                length,
            });
        }

        let mut bytes = vec![0; length as usize];
        self.source.read_exact(&mut bytes).await?;

        Ok(Packet {
            epoch_seconds,
            bytes,
        })
    }

    // strip headers based on link-layer type
    pub fn data<'a>(&self, packet: &'a [u8]) -> Result<&'a [u8], Error> {
        match self.data_link_type {
            DataLinkType::Ethernet => {
                let ether_type = &packet.get(12..14).ok_or(Error::InvalidPacket(
                    "ethernet packet less than 14 bytes".into(),
                ))?;
                let payload = &packet.get(14..).ok_or(Error::InvalidPacket(
                    "ethernet packet less than 15 bytes".into(),
                ))?;
                match ether_type {
                    [8, 0] => data_from_ipv4(payload),
                    [0x86, 0xDD] => data_from_ipv6(payload),
                    #[allow(clippy::indexing_slicing, reason = "ether_type is 2 bytes")]
                    _ => Err(Error::UnsupportedEtherType([ether_type[0], ether_type[1]])),
                }
            }
        }
    }
}

impl Reader<BufReader<File>> {
    pub async fn from_file(path: &str) -> Result<Self, Error> {
        let file = File::open(path).await?;
        let source = BufReader::new(file);

        Self::from_pcap_header(source).await
    }
}

fn data_from_ipv4(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < 20 {
        return Err(Error::InvalidIPHeader(format!(
            "missing complete IPv4 header, packet is only {} bytes",
            packet.len()
        )));
    }
    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let version = u8::from_be_bytes([packet[0] >> 4]);
    if version != 4 {
        return Err(Error::InvalidIPHeader(format!(
            "expected version 4, got version {version}"
        )));
    }

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let header_length = (u8::from_be_bytes([packet[0] & 0xF]) * 4) as usize;
    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let protocol = u8::from_be_bytes([packet[9]]);
    match protocol {
        6 => data_from_tcp(
            packet
                .get(header_length..total_length)
                .ok_or(Error::InvalidPacket(
                    "IPv4 packet shorter than length in header".into(),
                ))?,
        ),
        _ => Err(Error::UnsupportedProtocol(protocol)),
    }
}

fn data_from_ipv6(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < 40 {
        return Err(Error::InvalidIPHeader(format!(
            "missing complete IPv6 header, packet is only {} bytes",
            packet.len()
        )));
    }
    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
    let version = u8::from_be_bytes([packet[0] >> 4]);
    if version != 6 {
        return Err(Error::InvalidIPHeader(format!(
            "Expected version 6, got version {version}"
        )));
    }

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
    let length = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
    let protocol = u8::from_be_bytes([packet[6]]);
    match protocol {
        6 => data_from_tcp(packet.get(40..40 + length).ok_or(Error::InvalidPacket(
            "IPv6 packet shorter than length in header".into(),
        ))?),
        _ => Err(Error::UnsupportedProtocol(protocol)),
    }
}

fn data_from_tcp(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < 20 {
        return Err(Error::InvalidPacket(format!(
            "missing complete TCP header, packet is only {} bytes",
            packet.len()
        )));
    }

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let data_offset = (u8::from_be_bytes([packet[12] >> 4]) * 4) as usize;

    packet.get(data_offset..).ok_or(Error::InvalidPacket(
        "data offset from header beyond end of packet".into(),
    ))
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
