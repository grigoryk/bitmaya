use std::collections::HashMap;
use sha1::{Digest, Sha1};

pub struct PieceInProgress {
    pub index: u32,
    pub missing_bytes: u32
}

pub struct Piece {
    complete: bool,
    parts: Vec<u8>
}

#[derive(Debug)]
pub struct RequestPart {
    pub piece_index: u32,
    pub offset: u32
}
pub trait DataBuffer {
    fn to_bytes(self) -> Vec<u8>;
    fn len(&self) -> usize;
    fn next_to_request(&self) -> Option<RequestPart>;
    fn append(&mut self, index: u32, block: Vec<u8>);
    fn verify(&mut self, index: u32, pieces_hashes: &Vec<u8>, torrent_piece_length: u32) -> bool;
}

pub struct InMemoryData {
    pieces: HashMap<u32, Piece>
}
impl InMemoryData {
    pub fn new(num_pieces: u32) -> InMemoryData {
        let mut pieces = HashMap::new();
        for i in 0..num_pieces {
            pieces.insert(i, Piece { complete: false, parts: vec!() });
        }
        InMemoryData { pieces }
    }
}
impl DataBuffer for InMemoryData {
    fn to_bytes(self) -> Vec<u8> {
        let mut pieces = vec!();
        struct Piece {
            index: u32,
            data: Vec<u8>
        }
        for p in self.pieces.into_iter() {
            pieces.push(Piece { index: p.0, data: p.1.parts })
        }
        pieces.sort_by(|a, b| a.index.cmp(&b.index));
        let mut bx = vec!();
        for mut p in pieces {
            bx.append(&mut p.data);
        }
        bx
    }

    fn len(&self) -> usize {
        let mut l = 0;
        for p in self.pieces.values() {
            l += p.parts.len();
        }
        l
    }

    fn next_to_request(&self) -> Option<RequestPart> {
        println!("next_to_request, self.pieces.len={}", self.pieces.len());
        for i in 0..self.pieces.len() {
            println!("checking piece {}", i);
            if let Some(p) = self.pieces.get(&(i as u32)) {
                println!("got the piece, complete={}", p.complete);
                if !p.complete {
                    return Some(RequestPart { piece_index: i as u32, offset: p.parts.len() as u32 });
                }
            }
        }
        return None
    }

    fn append(&mut self, index: u32, mut block: Vec<u8>) {
        println!("appending block(len={}) to piece index={}", block.len(), index);
        match self.pieces.get_mut(&index) {
            Some(p) => {
                println!("appending .. current size: {}, new bytes={}", p.parts.len(), block.len());
                p.parts.append(&mut block);
                println!("appended... new size: {}", p.parts.len());
            },
            None => println!("couldn't find piece index to append block! index={}", index),
        }
    }

    fn verify(&mut self, index: u32, pieces_hashes: &Vec<u8>, torrent_piece_length: u32) -> bool {
        println!("verifying piece with index {}", index);
        match self.pieces.get_mut(&index) {
            Some(p) => {
                let piece = &p.parts;
                println!("piece length = {}", piece.len());
                let is_last_piece = (pieces_hashes.len() as u32 / 20 - 1) == index;
                if torrent_piece_length != piece.len() as u32 && !is_last_piece {
                    println!("torrent_piece_length = {}, piece len = {}, don't match, not verifying", torrent_piece_length, piece.len());
                    return false;
                } else if is_last_piece {
                    println!("is last piece, verifying");
                } else {
                    println!("torrent_piece_length matches piece len, verifying");
                }
                println!("hash slice: {:?}", (index as usize)..(index as usize+20));
                let expected_hash = match pieces_hashes.get((index as usize) * 20..(index as usize) * 20 + 20) {
                    Some(eh) => eh,
                    None => panic!("couldn't find expected hash for: {:?}", (index as usize)..(index as usize+20)),
                };
                println!("hash length: {}", expected_hash.len());
                let mut hasher = Sha1::new();
                hasher.update(piece);
                let piece_hash: [u8; 20] = match hasher.finalize().try_into() {
                    Ok(h) => h,
                    Err(_) => panic!("failed to hash piece, should not happen"),
                };
                println!("comparing hashes:");
                println!("expected: {:?}", expected_hash);
                println!("piece:    {:?}", piece_hash);
                if expected_hash == piece_hash {
                    println!("hashes match. marking piece complete, index={}", index);
                    p.complete = true;
                    true
                } else {
                    println!("hashes don't match");
                    false
                }
            },
            None => {
                println!("piece not found for index {}", index);
                false
            }
        }
    }
}
