use std::collections::HashMap;
use std::f32::consts::E;
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

impl Piece {
    pub fn hash(&self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(&self.parts);
        match hasher.finalize().try_into() {
            Ok(h) => h,
            Err(e) => panic!("failed to hash piece, should not happen. error: {}", e),
        }
    }
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
    fn total_byte_len(&self) -> usize;
    fn append_to_piece(&mut self, index: u32, block: Vec<u8>) -> Result<(), &'static str>;
    fn get_piece(&self, index: u32) -> Option<&Piece>;
    fn mark_piece_completed(&mut self, index: u32) -> Result<(), &'static str>;
}

pub trait DownloadStrategy {
    fn next_to_request(&self, buffer: &impl DataBuffer) -> Option<RequestPart>;
}

pub struct SequentialDownload;
impl DownloadStrategy for SequentialDownload {
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

pub struct OnDiskData {
    file: File

    // we'll get blocks belonging to random pieces
    // we know number of pieces (and length of each piece)
    // so for each block we know where to write_at(block_index+block_written_so_far_offset)
    // each parts file must "stand on its own" - should be able to restore its state, e.g.
    // so a naive implementation may be:
    //
}
impl OnDiskData {
    pub fn new(name: String, num_pieces: u32) -> std::io::Result<OnDiskData> {
        Ok(OnDiskData { file: File::open(name)? })
    }
}
impl DataBuffer for OnDiskData {
    fn state(&self) -> &DownloadState {
        todo!()
    }

    fn flush(self, files: &Vec<SizedFile>) -> Result<(), &'static str> {
        todo!()
    }

    fn total_byte_len(&self) -> usize {
        todo!()
    }

    fn append_to_piece(&mut self, index: u32, block: Vec<u8>) -> Result<(), &'static str> {
        todo!()
    }

    fn mark_piece_completed(&mut self, index: u32) -> Result<(), &'static str> {
        todo!()
    }

    fn get_piece(&self, index: u32) -> Option<&Piece> {
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

    fn total_byte_len(&self) -> usize {
        let mut l = 0;
        for p in self.pieces.values() {
            l += p.parts.len();
        }
        l
    }

    fn append_to_piece(&mut self, index: u32, mut block: Vec<u8>) -> Result<(), &'static str> {
        let block_len = block.len() as u32;
        println!("appending block(len={}) to piece index={}", block.len(), index);
        match self.pieces.get_mut(&index) {
            Some(p) => {
                println!("appending .. current size: {}, new bytes={}", p.parts.len(), block_len);
                p.parts.append(&mut block);
                if let Some(piece_state) = self.state.pieces.get_mut(&index) {
                    piece_state.parts_offset += block_len;
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

    fn mark_piece_completed(&mut self, index: u32) -> Result<(), &'static str> {
        println!("marking piece={} as completed", index);
        if let Some(piece_state) = self.state.pieces.get_mut(&index) {
            piece_state.complete = true;
            Ok(())
        } else {
            Err("mark_piece_completed: no such index")
        }
    }

    fn get_piece(&self, index: u32) -> Option<&Piece> {
        return self.pieces.get(&index);
    }
}
