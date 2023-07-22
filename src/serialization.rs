use crate::types::{PieceState, DownloadState};
use mescal::BencodeItem;

impl From<&PieceState> for BencodeItem {
    fn from(value: &PieceState) -> Self {
        BencodeItem::List(
            vec!(
                BencodeItem::Int(if value.complete { 1 } else { 0 }),
                BencodeItem::Int(value.parts_offset.into())
            ),
        )
    }
}

pub enum FromBencodeItemError {
    NotList,
    IndexParse,
    CompleteParse,
    PartsOffsetParse
}

impl TryFrom<&BencodeItem> for PieceState {
    type Error = FromBencodeItemError;

    fn try_from(value: &BencodeItem) -> Result<Self, Self::Error> {
        match value {
            BencodeItem::List(lx) => {
                Ok(PieceState {
                    complete: match lx[0] {
                        BencodeItem::Int(complete) => if complete == 1 { true } else { false },
                        _ => return Err(FromBencodeItemError::CompleteParse)
                    },
                    parts_offset: match lx[1] {
                        BencodeItem::Int(parts_offset) => parts_offset as u32,
                        _ => return Err(FromBencodeItemError::PartsOffsetParse)
                    }
                })
            },
            _ => Err(FromBencodeItemError::NotList)
        }
    }
}

impl From<&DownloadState> for BencodeItem {
    fn from(value: &DownloadState) -> Self {
        BencodeItem::List(
            value.pieces.iter().map(|v| v.into()).collect()
        )
    }
}

impl TryFrom<BencodeItem> for DownloadState {
    type Error = FromBencodeItemError;

    fn try_from(value: BencodeItem) -> Result<Self, Self::Error> {
        match value {
            BencodeItem::List(lx) => {
                let pieces: Result<Vec<PieceState>, Self::Error> = lx.iter().map(|v| PieceState::try_from(v)).collect();
                match pieces {
                    Ok(px) => Ok(DownloadState { pieces: px }),
                    Err(e) => Err(e),
                }
            },
            _ => Err(FromBencodeItemError::NotList)
        }
    }
}
