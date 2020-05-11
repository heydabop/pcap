#![allow(dead_code)]

mod error;

use std::error::Error;
use std::fs::File;
use std::io::Read;

pub struct Reader<T: Read> {
    reverse: bool,
    source: T,
    max_length: u32,
}

impl<T: Read> Reader<T> {
    fn parse_global_header(&mut self) -> Result<(), Box<dyn Error>> {
        let mut global_header = [0; 24];
        self.source.read_exact(&mut global_header)?;

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

        Ok(())
    }

    fn new(source: T) -> Result<Self, Box<dyn Error>> {
        let mut this = Self {
            source,
            reverse: false,
            max_length: 0,
        };

        if let Err(e) = this.parse_global_header() {
            return Err(e);
        }

        Ok(this)
    }

    fn read_packet(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut packet_header = [0; 16];
        self.source.read_exact(&mut packet_header)?;

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

        let mut packet = vec![0; length as usize];
        self.source.read_exact(&mut packet)?;

        return Ok(packet);
    }
}

impl Reader<File> {
    fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let source = File::open(path)?;

        let mut this = Self {
            source,
            reverse: false,
            max_length: 0,
        };

        if let Err(e) = this.parse_global_header() {
            return Err(e);
        }

        Ok(this)
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    #[test]
    fn new_from_reader() {
        let v: Vec<u8> = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
        ];
        Reader::new(v.as_slice()).unwrap();
    }

    #[test]
    fn read_from_reader() {
        let v: Vec<u8> = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
            0xa4, 0x93, 0xb8, 0x5e, 0xb6, 9, 0x0d, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4,
        ];
        let mut r = Reader::new(v.as_slice()).unwrap();
        assert_eq!(r.read_packet().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn new_from_file() {
        Reader::from_file("packets.pcap").unwrap();
    }
}
