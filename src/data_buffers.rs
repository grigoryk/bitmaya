use std::collections::HashMap;
use sha1::{Digest, Sha1};
use std::fs;
use std::fs::File;

use crate::types::SizedFile;

pub struct PieceInProgress {
    pub index: u32,
    pub missing_bytes: u32
}

pub struct Piece {
    parts: Vec<u8>
}

pub struct PieceState {
    complete: bool,
    parts_offset: u32
}

// common state of a buffer is:
// - list of pieces
// - is piece complete
// - piece parts offset for each piece
pub struct DownloadState {
    pieces: HashMap<u32, PieceState>
}

#[derive(Debug)]
pub struct RequestPart {
    pub piece_index: u32,
    pub offset: u32
}
pub trait DataBuffer {
    fn state(&self) -> &DownloadState;
    fn flush(self, files: &Vec<SizedFile>) -> Result<(), &'static str>;
    fn len(&self) -> usize;
    fn append(&mut self, index: u32, block: Vec<u8>) -> Result<(), &'static str>;
    fn verify(&mut self, index: u32, pieces_hashes: &Vec<u8>, torrent_piece_length: u32) -> Result<bool, &'static str>;
}

pub trait DownloadAlgorithm {
    fn next_to_request(&self, buffer: &impl DataBuffer) -> Option<RequestPart>;
}

pub struct SequentialDownload {}
impl DownloadAlgorithm for SequentialDownload {
    fn next_to_request(&self, buffer: &impl DataBuffer) -> Option<RequestPart> {
        let pieces = &buffer.state().pieces;
        for i in 0..pieces.len() {
            println!("checking piece {}", i);
            if let Some(p) = pieces.get(&(i as u32)) {
                println!("got the piece, complete={}", p.complete);
                if !p.complete {
                    return Some(RequestPart { piece_index: i as u32, offset: p.parts_offset });
                }
            }
        }
        return None
    }
}

pub struct PartsFileData {
    file: File

    // we'll get blocks belonging to random pieces
    // we know number of pieces (and length of each piece)
    // so for each block we know where to write_at(block_index+block_written_so_far_offset)
    // each parts file must "stand on its own" - should be able to restore its state, e.g.
    // so a naive implementation may be:
    //
}
impl PartsFileData {
    pub fn new(name: String, num_pieces: u32) -> std::io::Result<PartsFileData> {
        Ok(PartsFileData { file: File::open(name)? })
    }
}
impl DataBuffer for PartsFileData {
    fn state(&self) -> &DownloadState {
        todo!()
    }

    fn flush(self, files: &Vec<SizedFile>) -> Result<(), &'static str> {
        todo!()
    }

    fn len(&self) -> usize {
        todo!()
    }

    fn append(&mut self, index: u32, block: Vec<u8>) -> Result<(), &'static str> {
        todo!()
    }

    fn verify(&mut self, index: u32, pieces_hashes: &Vec<u8>, torrent_piece_length: u32) -> Result<bool, &'static str> {
        todo!()
    }
}

pub struct InMemoryData {
    state: DownloadState,
    pieces: HashMap<u32, Piece>
}
impl InMemoryData {
    pub fn new(num_pieces: u32) -> InMemoryData {
        let mut pieces = HashMap::new();
        let mut state = HashMap::new();
        for i in 0..num_pieces {
            pieces.insert(i, Piece { parts: vec!() });
            state.insert(i, PieceState { complete: false, parts_offset: 0 });
        }
        InMemoryData { state: DownloadState { pieces: state }, pieces }
    }

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
}
impl DataBuffer for InMemoryData {
    fn state(&self) -> &DownloadState {
        &self.state
    }

    fn flush(self, files: &Vec<SizedFile>) -> Result<(), &'static str> {
        let bytes = self.to_bytes();
        let mut wrote = 0;
        for file in files {
            println!("dumping to file {}", file.name);
            match fs::write(&file.name, bytes.get(wrote..file.length as usize).unwrap()) {
                Ok(_) => {
                    wrote += file.length as usize;
                },
                Err(e) => {
                    println!("error writing: {}", e);
                    return Err("error writing")
                }
            }
        }
        Ok(())
    }

    fn len(&self) -> usize {
        let mut l = 0;
        for p in self.pieces.values() {
            l += p.parts.len();
        }
        l
    }

    fn append(&mut self, index: u32, mut block: Vec<u8>) -> Result<(), &'static str> {
        println!("appending block(len={}) to piece index={}", block.len(), index);
        match self.pieces.get_mut(&index) {
            Some(p) => {
                println!("appending .. current size: {}, new bytes={}", p.parts.len(), block.len());
                p.parts.append(&mut block);
                if let Some(piece_state) = self.state.pieces.get_mut(&index) {
                    piece_state.parts_offset += block.len() as u32;
                } else {
                    panic!("download state not intact")
                };
                println!("appended... new size: {}", p.parts.len());
                Ok(())
            },
            None => {
                println!("couldn't find piece index to append block! index={}", index);
                Err("couldn't find piece index to append block")
            }
        }
    }

    fn verify(&mut self, index: u32, pieces_hashes: &Vec<u8>, torrent_piece_length: u32) -> Result<bool, &'static str> {
        println!("verifying piece with index {}", index);
        match self.pieces.get_mut(&index) {
            Some(p) => {
                let piece = &p.parts;
                println!("piece length = {}", piece.len());
                let is_last_piece = (pieces_hashes.len() as u32 / 20 - 1) == index;
                if torrent_piece_length != piece.len() as u32 && !is_last_piece {
                    println!("torrent_piece_length = {}, piece len = {}, don't match, not verifying", torrent_piece_length, piece.len());
                    return Ok(false);
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
                    if let Some(piece_state) = self.state.pieces.get_mut(&index) {
                        piece_state.complete = true;
                    } else {
                        panic!("download state not intact")
                    }
                    Ok(true)
                } else {
                    println!("hashes don't match");
                    Ok(false)
                }
            },
            None => {
                println!("piece not found for index {}", index);
                Ok(false)
            }
        }
    }
}
