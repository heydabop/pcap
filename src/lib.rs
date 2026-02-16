mod error;

use error::Error;
use std::net::IpAddr;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

const MICROSECONDS_BIG_ENDIAN: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
const NANOSECONDS_BIG_ENDIAN: [u8; 4] = [0xA1, 0xB2, 0x3C, 0xD4];
const MICROSECONDS_LITTLE_ENDIAN: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];
const NANOSECONDS_LITTLE_ENDIAN: [u8; 4] = [0xD4, 0x3C, 0xB2, 0xA1];

// https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-00.html#name-linktype-registry
#[derive(PartialEq, Eq, Clone, Copy)]
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

#[derive(Clone)]
pub struct Packet {
    data_link_type: DataLinkType,
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
            data_link_type: self.data_link_type,
            epoch_seconds,
            bytes,
        })
    }
}

impl Reader<BufReader<File>> {
    pub async fn from_file(path: &str) -> Result<Self, Error> {
        let file = File::open(path).await?;
        let source = BufReader::new(file);

        Self::from_pcap_header(source).await
    }
}

impl Packet {
    // strip headers based on link-layer type
    pub fn data(&self) -> Result<&[u8], Error> {
        match self.data_link_type {
            DataLinkType::Ethernet => {
                let (ether_type, payload) = self.ethertype_and_payload()?;

                match ether_type {
                    [8, 0] => data_from_ipv4(payload),
                    [0x86, 0xDD] => data_from_ipv6(payload),
                    #[allow(clippy::indexing_slicing, reason = "ether_type is 2 bytes")]
                    _ => Err(Error::UnsupportedEtherType([ether_type[0], ether_type[1]])),
                }
            }
        }
    }

    fn ethertype_and_payload(&self) -> Result<(&[u8], &[u8]), Error> {
        match self.data_link_type {
            DataLinkType::Ethernet => {
                let tag_or_type = &self.bytes.get(12..14).ok_or(Error::InvalidPacket(
                    "ethernet packet less than 14 bytes".into(),
                ))?;
                // 802.1Q tag (VLAN)
                let vlan_tagged = *tag_or_type == [0x81, 0x00];

                // if packet isn't VLAN tagged, the type is where the tag would start
                let ether_type = if vlan_tagged {
                    // if packet IS VLAN tagged, the type is 4 packets later
                    &self.bytes.get(16..18).ok_or(Error::InvalidPacket(
                        "VLAN tagged ethernet packet less than 18 bytes".into(),
                    ))?
                } else {
                    tag_or_type
                };
                // payload is immediately after ethertype, which is dependent on whether or not its VLAN tagged
                let payload = if vlan_tagged {
                    &self.bytes.get(18..).ok_or(Error::InvalidPacket(
                        "VLAN tagged ethernet packet less than 19 bytes".into(),
                    ))?
                } else {
                    &self.bytes.get(14..).ok_or(Error::InvalidPacket(
                        "ethernet packet less than 15 bytes".into(),
                    ))?
                };

                Ok((ether_type, payload))
            }
        }
    }

    pub fn source_ip_address(&self) -> Result<IpAddr, Error> {
        let (ether_type, payload) = self.ethertype_and_payload()?;

        match ether_type {
            [8, 0] => {
                validate_ipv4_packet(payload)?;
                #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                let bytes: [u8; 4] = payload[12..16].try_into()?;
                Ok(IpAddr::from(bytes))
            }
            [0x86, 0xDD] => {
                validate_ipv6_packet(payload)?;
                #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
                let bytes: [u8; 16] = payload[8..24].try_into()?;
                Ok(IpAddr::from(bytes))
            }
            #[allow(clippy::indexing_slicing, reason = "ether_type is 2 bytes")]
            _ => Err(Error::UnsupportedEtherType([ether_type[0], ether_type[1]])),
        }
    }

    pub fn destination_ip_address(&self) -> Result<IpAddr, Error> {
        let (ether_type, payload) = self.ethertype_and_payload()?;

        match ether_type {
            [8, 0] => {
                validate_ipv4_packet(payload)?;
                #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                let bytes: [u8; 4] = payload[16..20].try_into()?;
                Ok(IpAddr::from(bytes))
            }
            [0x86, 0xDD] => {
                validate_ipv6_packet(payload)?;
                #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
                let bytes: [u8; 16] = payload[24..40].try_into()?;
                Ok(IpAddr::from(bytes))
            }
            #[allow(clippy::indexing_slicing, reason = "ether_type is 2 bytes")]
            _ => Err(Error::UnsupportedEtherType([ether_type[0], ether_type[1]])),
        }
    }
}

fn validate_ipv4_packet(packet: &[u8]) -> Result<(), Error> {
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
    Ok(())
}

fn data_from_ipv4(packet: &[u8]) -> Result<&[u8], Error> {
    validate_ipv4_packet(packet)?;

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let header_length = (u8::from_be_bytes([packet[0] & 0xF]) * 4) as usize;
    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
    let protocol = u8::from_be_bytes([packet[9]]);
    let payload = packet
        .get(header_length..total_length)
        .ok_or(Error::InvalidPacket(
            "IPv4 packet shorter than length in header".into(),
        ))?;
    match protocol {
        6 => data_from_tcp(payload),
        17 => data_from_udp(payload),
        _ => Err(Error::UnsupportedProtocol(protocol)),
    }
}

fn validate_ipv6_packet(packet: &[u8]) -> Result<(), Error> {
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
    Ok(())
}

fn data_from_ipv6(packet: &[u8]) -> Result<&[u8], Error> {
    validate_ipv6_packet(packet)?;

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
    let length = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
    let protocol = u8::from_be_bytes([packet[6]]);
    let payload = packet.get(40..40 + length).ok_or(Error::InvalidPacket(
        "IPv6 packet shorter than length in header".into(),
    ))?;
    match protocol {
        6 => data_from_tcp(payload),
        17 => data_from_udp(payload),
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

fn data_from_udp(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < 8 {
        return Err(Error::InvalidPacket(format!(
            "missing complete UDP header, datagram is only {} bytes",
            packet.len()
        )));
    }

    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 8")]
    let length = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    packet.get(8..length).ok_or(Error::InvalidPacket(
        "data offset from header beyond end of packet".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn read_from_file() {
        let mut reader = Reader::from_file("packets.pcap").await.unwrap();
        let packet = reader.read_packet().await.unwrap();
        let data = packet.data().unwrap();
        assert!(data.is_empty());
        let source_ip_address = packet.source_ip_address().unwrap();
        let destination_ip_address = packet.destination_ip_address().unwrap();
        let loopback = IpAddr::from([127, 0, 0, 1]);
        assert_eq!(source_ip_address, loopback);
        assert_eq!(destination_ip_address, loopback);
        for _ in 0..7 {
            reader.read_packet().await.unwrap();
        }
        assert!(reader.read_packet().await.is_err());
    }

    #[tokio::test]
    async fn data() {
        let packet = Packet {
            data_link_type: DataLinkType::Ethernet,
            epoch_seconds: 0,
            bytes: vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                0x45, 0x00, 0x00, 0x43, 0xdb, 0xb5, 0x00, 0x00, 0x40, 0x06, 0xa0, 0xfd, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x98, 0x77, 0x1e, 0x61, 0x40, 0x4a, 0xf2, 0x2b,
                0xbf, 0xe5, 0xf2, 0x2e, 0x80, 0x18, 0x02, 0x00, 0xfe, 0x37, 0x00, 0x00, 0x01, 0x01,
                0x08, 0x0a, 0x60, 0xed, 0x00, 0x35, 0x60, 0xed, 0x00, 0x30, 0x0f, 0x00, 0x01, 0x0b,
                0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39, 0x34,
            ],
        };
        let data = packet.data().unwrap();
        assert_eq!(
            data,
            [
                0x0f, 0x00, 0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39,
                0x34,
            ]
        );

        let packet = Packet {
            data_link_type: DataLinkType::Ethernet,
            epoch_seconds: 0,
            bytes: vec![
                0x4c, 0xcc, 0x6a, 0x49, 0x25, 0xd4, 0x48, 0x5b, 0x39, 0x7b, 0x25, 0x19, 0x08, 0x00,
                0x45, 0x00, 0x00, 0x37, 0xe2, 0x04, 0x40, 0x00, 0x80, 0x06, 0x94, 0xd9, 0xc0, 0xa8,
                0x01, 0x8f, 0xc0, 0xa8, 0x01, 0x03, 0xcd, 0x6e, 0x1e, 0x61, 0xc5, 0x33, 0xee, 0x9f,
                0x06, 0x51, 0xff, 0xc4, 0x50, 0x18, 0x20, 0x14, 0x5f, 0x1d, 0x00, 0x00, 0x0f, 0x00,
                0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39, 0x34,
            ],
        };
        let data2 = packet.data().unwrap();
        assert_eq!(
            data2,
            [
                0x0f, 0x00, 0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39,
                0x34,
            ]
        );
    }

    #[tokio::test]
    async fn ipv4_address() {
        let mut reader = Reader::from_file("tcpping4.pcap").await.unwrap();
        let packet = reader.read_packet().await.unwrap();
        let source_ip_address = packet.source_ip_address().unwrap();
        assert_eq!(source_ip_address, IpAddr::from([192, 168, 1, 2]));
        let desintation_ip_address = packet.destination_ip_address().unwrap();
        assert_eq!(desintation_ip_address, IpAddr::from([192, 168, 1, 1]));
    }

    #[tokio::test]
    async fn ipv6_address() {
        let mut reader = Reader::from_file("tcpping6.pcap").await.unwrap();
        let packet = reader.read_packet().await.unwrap();
        let source_ip_address = packet.source_ip_address().unwrap();
        assert_eq!(
            source_ip_address,
            "fe80::2e0:4cff:fe68:6352".parse::<IpAddr>().unwrap()
        );
        let desintation_ip_address = packet.destination_ip_address().unwrap();
        assert_eq!(
            desintation_ip_address,
            "fe80::51d8:8e97:c7e5:b925".parse::<IpAddr>().unwrap()
        );
    }
}
