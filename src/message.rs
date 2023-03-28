enum Message {
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
    fn to_bytes(&self) -> Vec<u8> {
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
                // NB: to_be_bytes (be=big-endian) is the same as doing this:
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
    }

    #[test]
    fn choke() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x0), Message::Choke.to_bytes());
    }

    #[test]
    fn unchoke() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x1), Message::Unchoke.to_bytes());
    }

    #[test]
    fn interested() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x2), Message::Interested.to_bytes());
    }

    #[test]
    fn notinterested() {
        assert_eq!(vec!(0x0, 0x0, 0x0, 0x1, 0x3), Message::NotInterested.to_bytes());
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