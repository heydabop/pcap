use crate::{DataLink, Network, Transport, error::Error};
use std::net::IpAddr;

#[derive(Clone)]
pub struct Packet {
    // packet timestamp in seconds
    epoch_seconds: u32,
    // packet data
    bytes: Vec<u8>,
    // data link of packet
    data_link: DataLink,
    // start index in bytes of data link payload (the start of the network packet)
    data_link_payload_start_index: Option<usize>,
    // network type of packet
    network: Option<Network>,
    // the start and end indices of the network packet's payload (the start of the transport packet)
    network_payload_indices: Option<(usize, usize)>,
    // transport type of packet
    transport: Option<Transport>,
}

// Most functions here borrow Packet mutably as the goal is to compute frames, payloads, their boundries, etc. once and save that information to the packet
// Instead of finding bytes in the packet every time a property of the packet is read
impl Packet {
    #[must_use]
    pub fn new(data_link: DataLink, epoch_seconds: u32, bytes: Vec<u8>) -> Self {
        Self {
            epoch_seconds,
            bytes,
            data_link,
            data_link_payload_start_index: None,
            network: None,
            network_payload_indices: None,
            transport: None,
        }
    }

    #[must_use]
    pub fn epoch_seconds(&self) -> u32 {
        self.epoch_seconds
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn data_link(&self) -> DataLink {
        self.data_link
    }

    pub fn network(&mut self) -> Result<Option<Network>, Error> {
        // quick return network if its already been computed
        if self.network.is_some() {
            return Ok(self.network);
        }
        match self.data_link {
            DataLink::Ethernet => {
                let tag_or_type = self.bytes.get(12..14).ok_or(Error::InvalidPacket(
                    "ethernet packet less than 14 bytes".into(),
                ))?;
                // 802.1Q tag (VLAN)
                let vlan_tagged = *tag_or_type == [0x81, 0x00];

                // if packet isn't VLAN tagged, the type is where the tag would start
                let ethertype = if vlan_tagged {
                    // if packet IS VLAN tagged, the type is 4 packets later
                    self.bytes.get(16..18).ok_or(Error::InvalidPacket(
                        "VLAN tagged ethernet packet less than 18 bytes".into(),
                    ))?
                } else {
                    tag_or_type
                };
                // payload is immediately after ethertype, which is dependent on whether or not its VLAN tagged
                let payload_start = if vlan_tagged { 18 } else { 14 };
                if self.bytes.get(payload_start..).is_none() {
                    return Err(Error::InvalidPacket(format!(
                        "ethernet packet less than {} bytes",
                        payload_start + 1
                    )));
                }

                self.network = Some(Network::try_from_ethertype(ethertype)?);
                self.data_link_payload_start_index = Some(payload_start);
            }
        }
        Ok(self.network)
    }

    pub fn transport(&mut self) -> Result<Option<Transport>, Error> {
        // quick return transport if its already been computed
        if self.transport.is_some() {
            return Ok(self.transport);
        }

        if let Some(network) = self.network()?
            && let Some(payload_start) = self.data_link_payload_start_index
        {
            // get just network payload (transport layer) of packet
            let payload = self
                .bytes
                .get(payload_start..)
                .ok_or(Error::InvalidIndex(payload_start, self.bytes.len()))?;
            match network {
                Network::IPv4 => {
                    validate_ipv4_packet(payload)?;

                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                    let header_length = (u8::from_be_bytes([payload[0] & 0xF]) * 4) as usize;
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                    let total_length = u16::from_be_bytes([payload[2], payload[3]]) as usize;

                    // parse transport type
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                    let transport = Some(Transport::try_from(u8::from_be_bytes([payload[9]]))?);
                    self.transport = transport;
                    // get IPv4 payload start and end
                    let indices = (payload_start + header_length, payload_start + total_length);
                    if self.bytes.get(indices.0..indices.1).is_none() {
                        return Err(Error::InvalidPacket(
                            "IPv4 packet shorter than length in header".into(),
                        ));
                    }
                    self.network_payload_indices = Some(indices);
                }
                Network::IPv6 => {
                    validate_ipv6_packet(payload)?;

                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
                    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;

                    // parse transport type
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
                    let transport = Some(Transport::try_from(u8::from_be_bytes([payload[6]]))?);
                    self.transport = transport;
                    // get IPv6 payload start and end
                    let indices = (payload_start + 40, payload_start + 40 + length);
                    if self.bytes.get(indices.0..indices.1).is_none() {
                        return Err(Error::InvalidPacket(
                            "IPv6 packet shorter than length in header".into(),
                        ));
                    }
                    self.network_payload_indices = Some(indices);
                }
            }
        }
        Ok(self.transport)
    }

    // returns just transport layer payload
    pub fn data(&mut self) -> Result<&[u8], Error> {
        if let Some(transport) = self.transport()?
            && let Some(indices) = self.network_payload_indices
        {
            // get just network layer payload (transport packet)
            let payload = self
                .bytes
                .get(indices.0..indices.1)
                .ok_or(Error::InvalidIndex(indices.1, self.bytes.len()))?;
            match transport {
                Transport::Tcp => {
                    if payload.len() < 20 {
                        return Err(Error::InvalidPacket(format!(
                            "missing complete TCP header, packet is only {} bytes",
                            payload.len()
                        )));
                    }

                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                    let data_offset = (u8::from_be_bytes([payload[12] >> 4]) * 4) as usize;

                    payload.get(data_offset..).ok_or(Error::InvalidPacket(
                        "data offset from header beyond end of packet".into(),
                    ))
                }
                Transport::Udp => {
                    if payload.len() < 8 {
                        return Err(Error::InvalidPacket(format!(
                            "missing complete UDP header, datagram is only {} bytes",
                            payload.len()
                        )));
                    }

                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 8")]
                    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;

                    payload.get(8..length).ok_or(Error::InvalidPacket(
                        "data offset from header beyond end of packet".into(),
                    ))
                }
            }
        } else {
            Err(Error::EmptyPacket)
        }
    }

    pub fn source_ip_address(&mut self) -> Result<Option<IpAddr>, Error> {
        if let Some(network) = self.network()?
            && let Some(payload_start) = self.data_link_payload_start_index
        {
            let payload = self
                .bytes
                .get(payload_start..)
                .ok_or(Error::InvalidIndex(payload_start, self.bytes.len()))?;
            match network {
                Network::IPv4 => {
                    validate_ipv4_packet(payload)?;
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                    let bytes: [u8; 4] = payload[12..16].try_into()?;
                    Ok(Some(IpAddr::from(bytes)))
                }
                Network::IPv6 => {
                    validate_ipv6_packet(payload)?;
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
                    let bytes: [u8; 16] = payload[8..24].try_into()?;
                    Ok(Some(IpAddr::from(bytes)))
                }
            }
        } else {
            Ok(None)
        }
    }

    pub fn source_port(&mut self) -> Result<Option<u16>, Error> {
        if let Some(transport) = self.transport()?
            && let Some(indices) = self.network_payload_indices
        {
            // get just network layer payload (transport packet)
            let payload = self
                .bytes
                .get(indices.0..indices.1)
                .ok_or(Error::InvalidIndex(indices.1, self.bytes.len()))?;
            match transport {
                Transport::Tcp => {
                    if payload.len() < 20 {
                        return Err(Error::InvalidPacket(format!(
                            "missing complete TCP header, packet is only {} bytes",
                            payload.len()
                        )));
                    }

                    #[allow(clippy::indexing_slicing, reason = "checked payload len >= 20")]
                    Ok(Some(u16::from_be_bytes([payload[0], payload[1]])))
                }
                Transport::Udp => {
                    if payload.len() < 8 {
                        return Err(Error::InvalidPacket(format!(
                            "missing complete UDP header, datagram is only {} bytes",
                            payload.len()
                        )));
                    }

                    #[allow(clippy::indexing_slicing, reason = "checked payload len >= 8")]
                    Ok(Some(u16::from_be_bytes([payload[0], payload[1]])))
                }
            }
        } else {
            Ok(None)
        }
    }

    pub fn destination_ip_address(&mut self) -> Result<Option<IpAddr>, Error> {
        if let Some(network) = self.network()?
            && let Some(payload_start) = self.data_link_payload_start_index
        {
            let payload = self
                .bytes
                .get(payload_start..)
                .ok_or(Error::InvalidIndex(payload_start, self.bytes.len()))?;
            match network {
                Network::IPv4 => {
                    validate_ipv4_packet(payload)?;
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 20")]
                    let bytes: [u8; 4] = payload[16..20].try_into()?;
                    Ok(Some(IpAddr::from(bytes)))
                }
                Network::IPv6 => {
                    validate_ipv6_packet(payload)?;
                    #[allow(clippy::indexing_slicing, reason = "checked packet length >= 40")]
                    let bytes: [u8; 16] = payload[24..40].try_into()?;
                    Ok(Some(IpAddr::from(bytes)))
                }
            }
        } else {
            Ok(None)
        }
    }

    pub fn destination_port(&mut self) -> Result<Option<u16>, Error> {
        if let Some(transport) = self.transport()?
            && let Some(indices) = self.network_payload_indices
        {
            // get just network layer payload (transport packet)
            let payload = self
                .bytes
                .get(indices.0..indices.1)
                .ok_or(Error::InvalidIndex(indices.1, self.bytes.len()))?;
            match transport {
                Transport::Tcp => {
                    if payload.len() < 20 {
                        return Err(Error::InvalidPacket(format!(
                            "missing complete TCP header, packet is only {} bytes",
                            payload.len()
                        )));
                    }

                    #[allow(clippy::indexing_slicing, reason = "checked payload len >= 20")]
                    Ok(Some(u16::from_be_bytes([payload[2], payload[3]])))
                }
                Transport::Udp => {
                    if payload.len() < 8 {
                        return Err(Error::InvalidPacket(format!(
                            "missing complete UDP header, datagram is only {} bytes",
                            payload.len()
                        )));
                    }

                    #[allow(clippy::indexing_slicing, reason = "checked payload len >= 8")]
                    Ok(Some(u16::from_be_bytes([payload[2], payload[3]])))
                }
            }
        } else {
            Ok(None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::Reader;

    #[test]
    fn data() {
        let mut packet = Packet::new(
            DataLink::Ethernet,
            0,
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                0x45, 0x00, 0x00, 0x43, 0xdb, 0xb5, 0x00, 0x00, 0x40, 0x06, 0xa0, 0xfd, 0x7f, 0x00,
                0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x98, 0x77, 0x1e, 0x61, 0x40, 0x4a, 0xf2, 0x2b,
                0xbf, 0xe5, 0xf2, 0x2e, 0x80, 0x18, 0x02, 0x00, 0xfe, 0x37, 0x00, 0x00, 0x01, 0x01,
                0x08, 0x0a, 0x60, 0xed, 0x00, 0x35, 0x60, 0xed, 0x00, 0x30, 0x0f, 0x00, 0x01, 0x0b,
                0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39, 0x34,
            ],
        );
        let data = packet.data().unwrap();
        assert_eq!(
            data,
            [
                0x0f, 0x00, 0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39,
                0x34,
            ]
        );

        let mut packet = Packet::new(
            DataLink::Ethernet,
            0,
            vec![
                0x4c, 0xcc, 0x6a, 0x49, 0x25, 0xd4, 0x48, 0x5b, 0x39, 0x7b, 0x25, 0x19, 0x08, 0x00,
                0x45, 0x00, 0x00, 0x37, 0xe2, 0x04, 0x40, 0x00, 0x80, 0x06, 0x94, 0xd9, 0xc0, 0xa8,
                0x01, 0x8f, 0xc0, 0xa8, 0x01, 0x03, 0xcd, 0x6e, 0x1e, 0x61, 0xc5, 0x33, 0xee, 0x9f,
                0x06, 0x51, 0xff, 0xc4, 0x50, 0x18, 0x20, 0x14, 0x5f, 0x1d, 0x00, 0x00, 0x0f, 0x00,
                0x01, 0x0b, 0x54, 0x65, 0x72, 0x72, 0x61, 0x72, 0x69, 0x61, 0x31, 0x39, 0x34,
            ],
        );
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
        let mut packet = reader.read_packet().await.unwrap();
        let source_ip_address = packet.source_ip_address().unwrap();
        assert_eq!(source_ip_address, Some(IpAddr::from([192, 168, 1, 2])));
        let desintation_ip_address = packet.destination_ip_address().unwrap();
        assert_eq!(desintation_ip_address, Some(IpAddr::from([192, 168, 1, 1])));
    }

    #[tokio::test]
    async fn ipv6_address() {
        let mut reader = Reader::from_file("tcpping6.pcap").await.unwrap();
        let mut packet = reader.read_packet().await.unwrap();
        let source_ip_address = packet.source_ip_address().unwrap();
        assert_eq!(
            source_ip_address,
            Some("fe80::2e0:4cff:fe68:6352".parse::<IpAddr>().unwrap())
        );
        let desintation_ip_address = packet.destination_ip_address().unwrap();
        assert_eq!(
            desintation_ip_address,
            Some("fe80::51d8:8e97:c7e5:b925".parse::<IpAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn source_port() {
        let mut reader4 = Reader::from_file("tcpping4.pcap").await.unwrap();
        let mut packet4 = reader4.read_packet().await.unwrap();
        let source_port4 = packet4.source_port().unwrap();
        assert_eq!(source_port4, Some(58219));
        let mut reader6 = Reader::from_file("tcpping6.pcap").await.unwrap();
        let mut packet6 = reader6.read_packet().await.unwrap();
        let source_port6 = packet6.source_port().unwrap();
        assert_eq!(source_port6, Some(35155));
    }

    #[tokio::test]
    async fn destination_port() {
        let mut reader4 = Reader::from_file("tcpping4.pcap").await.unwrap();
        let mut packet4 = reader4.read_packet().await.unwrap();
        let destination_port4 = packet4.destination_port().unwrap();
        assert_eq!(destination_port4, Some(81));
        let mut reader6 = Reader::from_file("tcpping6.pcap").await.unwrap();
        let mut packet6 = reader6.read_packet().await.unwrap();
        let destination_port6 = packet6.destination_port().unwrap();
        assert_eq!(destination_port6, Some(81));
    }
}
