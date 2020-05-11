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
        let mut global_header = vec![0; 24];
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
    fn new_from_file() {
        Reader::from_file("packets.pcap").unwrap();
    }
}
