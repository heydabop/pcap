use crate::{DataLinkType, error::Error, packet::Packet};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

const MICROSECONDS_BIG_ENDIAN: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
const NANOSECONDS_BIG_ENDIAN: [u8; 4] = [0xA1, 0xB2, 0x3C, 0xD4];
const MICROSECONDS_LITTLE_ENDIAN: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1];
const NANOSECONDS_LITTLE_ENDIAN: [u8; 4] = [0xD4, 0x3C, 0xB2, 0xA1];

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

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
}
