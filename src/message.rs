use core::slice::Iter;

#[derive(PartialEq, Debug)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have { piece_index: u32 },
    Bitfield { bitfield: Vec<u8> },
    Request { index: u32, begin: u32, length: u32 },
    Piece { index: u32, begin: u32, block: Vec<u8> },
    Cancel { index: u32, begin: u32, length: u32 },
    Port { listen_port: u16 }
}

impl Message {
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, &'static str> {
        let length = match bytes.get(0..4) {
            Some(bx) => u32::from_be_bytes([bx[0], bx[1], bx[2], bx[3]]),
            None => return Err("missing length bytes"),
        };
        let id_maybe = bytes.get(4);
        match id_maybe {
            Some(id) => {
                match id {
                    0 => Ok(Message::Choke),
                    1 => Ok(Message::Unchoke),
                    2 => Ok(Message::Interested),
                    3 => Ok(Message::NotInterested),
                    4 => { // Have
                        match bytes.get(5..9) {
                            Some(bx) => {
                                Ok(Message::Have {
                                    piece_index: u32::from_be_bytes([bx[0], bx[1], bx[2], bx[3]])
                                })
                            },
                            None => return Err("Have message missing piece_index"),
                        }
                    },
                    5 => { // Bitfield
                        let bitfield_bytes = (length - 1) as usize; // err....
                        match bytes.get(5..5+bitfield_bytes) {
                            Some(bx) => Ok(Message::Bitfield { bitfield: bx.to_vec() }),
                            None => return Err("Missing bitfield bytes"),
                        }
                    }
                    _ => return Err("unknown message id")
                }
            },
            None => {
                if length > 0 {
                    return Err("non-zero length but missing id byte")
                }
                return Ok(Message::KeepAlive)
            },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bx = vec!();
        match self {
            Message::KeepAlive => {
                bx.push(0x0);
                bx.push(0x0);
                bx.push(0x0);
                bx.push(0x0);
            },
            Message::Choke | Message::Unchoke | Message::Interested | Message::NotInterested => {
                bx.append(&mut self.get_length().to_be_bytes().to_vec());
                bx.push(self.get_id().unwrap());
            },
            Message::Have { piece_index } => {
                bx.append(&mut self.get_length().to_be_bytes().to_vec());
                bx.push(self.get_id().unwrap());
                bx.append(&mut piece_index.to_be_bytes().to_vec());
                // NB: to_be_bytes (be=big-endian) is roughly this:
                // bx.push(((piece_index & 0xFF000000) >> 24) as u8);
                // bx.push(((piece_index & 0x00FF0000) >> 16) as u8);
                // bx.push(((piece_index & 0x0000FF00) >> 8) as u8);
                // bx.push((piece_index & 0x000000FF) as u8);
            },
            Message::Bitfield { bitfield } => {
                bx.append(&mut self.get_length().to_be_bytes().to_vec());
                bx.push(self.get_id().unwrap());
                bx.append(&mut bitfield.clone());
            }
            Message::Request { index, begin, length } => todo!(),
            Message::Piece { index, begin, block } => todo!(),
            Message::Cancel { index, begin, length } => todo!(),
            Message::Port { listen_port } => todo!(),
        }
        bx
    }

    fn get_id(&self) -> Option<u8> {
        match self {
            Message::KeepAlive => None,
            Message::Choke => Some(0),
            Message::Unchoke => Some(1),
            Message::Interested => Some(2),
            Message::NotInterested => Some(3),
            Message::Have { piece_index: _ } => Some(4),
            Message::Bitfield { bitfield: _ } => Some(5),
            Message::Request { index: _, begin: _, length: _ } => Some(6),
            Message::Piece { index: _, begin: _, block: _ } => Some(7),
            Message::Cancel { index: _, begin: _, length: _ } => Some(8),
            Message::Port { listen_port: _ } => Some(9),
        }
    }

    fn get_length(&self) -> u32 {
        match self {
            Message::KeepAlive => 0,
            Message::Choke => 1,
            Message::Unchoke => 1,
            Message::Interested => 1,
            Message::NotInterested => 1,
            Message::Have { piece_index: _ } => 5,
            Message::Bitfield { bitfield } => 1 + bitfield.len() as u32,
            Message::Request { index: _, begin: _, length: _ } => 13, // 1 (id) + 3 x (4 bytes)
            Message::Piece { index: _, begin: _, block } => 9 + block.len() as u32, // 1 (id) + 2 x (4 bytes) + block len
            Message::Cancel { index: _, begin: _, length: _ } => 13,
            Message::Port { listen_port: _ } => 3, // 1 (id) + port just gets 2 bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn keepalive() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x0), Message::KeepAlive.to_bytes());
        assert_eq!(Message::KeepAlive, Message::from_bytes(&[0x0, 0x0, 0x0, 0x0]).expect(""))
    }

    #[test]
    fn choke() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x0), Message::Choke.to_bytes());
        assert_eq!(Message::Choke, Message::from_bytes(&[0x0, 0x0, 0x0, 0x1, 0x0]).expect(""))
    }

    #[test]
    fn unchoke() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x1), Message::Unchoke.to_bytes());
        assert_eq!(Message::Unchoke, Message::from_bytes(&[0x0, 0x0, 0x0, 0x1, 0x1]).expect(""))
    }

    #[test]
    fn interested() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x2), Message::Interested.to_bytes());
        assert_eq!(Message::Interested, Message::from_bytes(&[0x0, 0x0, 0x0, 0x1, 0x2]).expect(""))
    }

    #[test]
    fn notinterested() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x3), Message::NotInterested.to_bytes());
        assert_eq!(Message::NotInterested, Message::from_bytes(&[0x0, 0x0, 0x0, 0x1, 0x3]).expect(""))
    }

    #[test]
    fn have() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x0, 0x0), Message::Have { piece_index: 0 }.to_bytes());
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x0, 0x1), Message::Have { piece_index: 1 }.to_bytes());
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x0, 0xFF), Message::Have { piece_index: 255 }.to_bytes());
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x01, 0x0), Message::Have { piece_index: 256 }.to_bytes());
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x01, 0x0, 0x0), Message::Have { piece_index: 65536 }.to_bytes());
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0x01, 0x00, 0x0, 0x0), Message::Have { piece_index: 16777216 }.to_bytes());
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x5, 0x4, 0xff, 0xff, 0xff, 0xff), Message::Have { piece_index: 4294967295 }.to_bytes());

        assert_eq!(Message::Have { piece_index: 0 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x0, 0x0]).expect(""));
        assert_eq!(Message::Have { piece_index: 1 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x0, 0x1]).expect(""));
        assert_eq!(Message::Have { piece_index: 255 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x0, 0xFF]).expect(""));
        assert_eq!(Message::Have { piece_index: 256 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x0, 0x01, 0x0]).expect(""));
        assert_eq!(Message::Have { piece_index: 65536 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0x0, 0x01, 0x0, 0x0]).expect(""));
        assert_eq!(Message::Have { piece_index: 16777216 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0x01, 0x0, 0x0, 0x0]).expect(""));
        assert_eq!(Message::Have { piece_index: 4294967295 }, Message::from_bytes(&[0x0, 0x0, 0x0, 0x5, 0x4, 0xff, 0xff, 0xff, 0xff]).expect(""));
    }

    #[test]
    fn bitfield() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x3, 0x5, 0x11, 0x10), Message::Bitfield { bitfield: vec!(0x11, 0x10) }.to_bytes());
        let vec_254: Vec<u8> = std::iter::repeat(0).take(254).collect();
        let mut bitfield_bytes = vec!(0x0, 0x0, 0x0, 0xff, 0x5);
        bitfield_bytes.append(&mut vec_254.clone());
        assert_eq!(bitfield_bytes, Message::Bitfield { bitfield: vec_254.clone() }.to_bytes());

        let mut bitfield_bytes = vec!(0x0, 0x0, 0x01, 0x00, 0x5);
        bitfield_bytes.append(&mut vec_254.clone());
        bitfield_bytes.push(0x10);
        let mut bitfield = vec_254.clone();
        bitfield.push(0x10);
        assert_eq!(bitfield_bytes, Message::Bitfield { bitfield }.to_bytes());
    }
}