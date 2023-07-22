#[derive(Debug)]
pub struct SizedFile {
    pub name: String,
    pub length: u64
}

pub struct PieceState {
    pub complete: bool,
    pub parts_offset: u32
}

// common state of a buffer is:
// - list of pieces
// - is piece complete
// - piece parts offset for each piece
pub struct DownloadState {
    pub pieces: Vec<PieceState>
}