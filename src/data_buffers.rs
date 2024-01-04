use std::{collections::HashMap, fs::OpenOptions};
use std::os::unix::prelude::FileExt;
use mescal::{BencodeItem, AsBencodeBytes};
use sha1::{Digest, Sha1};
use std::fs;
use std::fs::File;

use crate::types::{SizedFile, DownloadState, PieceState};

#[derive(Debug, Eq, PartialEq)]
pub struct PieceInProgress {
    pub index: u32,
    pub missing_bytes: usize
}

#[derive(Debug, Clone)]
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
            if let Some(p) = pieces.get(i) {
                if !p.complete {
                    return Some(RequestPart { piece_index: i as u32, offset: p.parts_offset });
                }
            }
        }
        return None
    }
}

pub struct OnDiskData {
    state: DownloadState,
    file: File,
    current_state_size: usize,

    // we'll get blocks belonging to random pieces
    // we know number of pieces (and length of each piece)
    // so for each block we know where to write_at(block_index+block_written_so_far_offset)
    // each parts file must "stand on its own" - should be able to restore its state, e.g.
    // so a naive implementation may be:
    //
}
impl OnDiskData {
    pub fn new(name: String, num_pieces: u32) -> std::io::Result<OnDiskData> {
        let mut state = vec!();
        for _ in 0..num_pieces {
            state.push(PieceState { complete: false, parts_offset: 0 });
        }
        let file = OpenOptions::new().write(true).create(true).open(name)?;
        let state = DownloadState { pieces: state };
        let constant_state_size = OnDiskData::persist_state_static(&file, &state)?;
        Ok(OnDiskData { file, state, current_state_size: constant_state_size })
    }

    fn persist_state(&mut self) {
        match OnDiskData::persist_state_static(&self.file, &self.state) {
            Ok(written) => self.current_state_size = written,
            Err(_) => panic!("couldn't persist state"),
        }
    }

    fn persist_state_static(file: &File, state: &DownloadState) -> Result<usize, std::io::Error> {
        let state = BencodeItem::from(state);
        file.write_at(&state.as_bytes(), 0)
    }
}
impl DataBuffer for OnDiskData {
    fn state(&self) -> &DownloadState {
        &self.state
    }

    fn flush(self, files: &Vec<SizedFile>) -> Result<(), &'static str> {
        todo!()
    }

    fn total_byte_len(&self) -> usize {
        let mut pieces = 0;
        for piece in &self.state.pieces {
            pieces = pieces + piece.parts_offset;
        }
        self.current_state_size + pieces as usize
    }

    fn append_to_piece(&mut self, index: u32, block: Vec<u8>) -> Result<(), &'static str> {
        if let Some(piece_state) = self.state.pieces.get_mut(index as usize) {
            piece_state.parts_offset += block.len() as u32;
        } else {
            panic!("download state not intact")
        };
        // todo write to disk
        self.persist_state();
        Ok(())
    }

    fn mark_piece_completed(&mut self, index: u32) -> Result<(), &'static str> {
        if let Some(piece_state) = self.state.pieces.get_mut(index as usize) {
            piece_state.complete = true;
            self.persist_state();
            Ok(())
        } else {
            Err("mark_piece_completed: no such index")
        }
    }

    fn get_piece(&self, index: u32) -> Option<&Piece> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct InMemoryData {
    state: DownloadState,
    pieces: HashMap<u32, Piece>
}
impl InMemoryData {
    pub fn new(num_pieces: u32) -> InMemoryData {
        let mut pieces = HashMap::new();
        let mut state = vec!();
        for i in 0..num_pieces {
            pieces.insert(i, Piece { parts: vec!() });
            state.push(PieceState { complete: false, parts_offset: 0 });
        }
        InMemoryData { state: DownloadState { pieces: state }, pieces }
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut pieces = vec!();
        struct Piece {
            index: u32,
            data: Vec<u8>
        }
        for (piece_index, piece_data) in self.pieces.into_iter() {
            pieces.push(Piece { index: piece_index, data: piece_data.parts })
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
                if let Some(piece_state) = self.state.pieces.get_mut(index as usize) {
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
        if let Some(piece_state) = self.state.pieces.get_mut(index as usize) {
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
