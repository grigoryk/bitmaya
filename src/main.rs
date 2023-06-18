use std::time::Duration;
use std::{env, collections::HashMap};
use form_urlencoded::byte_serialize;
use mescal::{BencodeItem, AsBencodeBytes, ByteString};
use sha1::{Sha1, Digest};
use std::error::Error;
use std::io::{Read, Write};
use url::Url;
use std::net::{TcpStream, SocketAddr, Shutdown, IpAddr, Ipv4Addr};
use std::fmt;
use std::str::from_utf8;

mod types;
mod message;
mod data_buffers;

use crate::message::Message;
use crate::data_buffers::{DataBuffer, InMemoryData, SequentialDownload, DownloadStrategy};

use crate::data_buffers::PieceInProgress;

const CLIENT_ID: &str = "-BM0010-123456789012";

#[derive(Debug)]
enum PeerState {
    NotChokingNotInterested,
    NotChokingInterested,
    ChokingNotInterested,
    ChokingInterested
}

#[derive(Debug)]
struct Peer {
    addr: [u8; 6],
    us: PeerState,
    them: PeerState
}

impl Peer {
    fn new(addr: [u8; 6]) -> Self {
        Peer {
            addr,
            us: PeerState::ChokingNotInterested,
            them: PeerState::ChokingNotInterested
        }
    }
}

trait InfoHash {
    fn info_hash(&self) -> String;
    fn info_hash_bytes(&self) -> [u8; 20];
}

#[derive(Debug)]
struct Tracker {
    announce_url: String,
    tracker_id: Option<String>,
    interval: Option<i64>,
    min_interval: Option<i64>,
}

#[derive(Debug)]
struct AllHashes {
    hashes: Vec<u8>
}
impl AllHashes {
    fn new(hashes: Vec<u8>) -> AllHashes {
        AllHashes { hashes: hashes }
    }
    fn len(&self) -> usize {
        self.hashes.len()
    }
    fn hash_for_index(&self, index: u32) -> &[u8] {
        match self.hashes.get((index as usize) * 20..(index as usize) * 20 + 20) {
            Some(eh) => eh,
            None => panic!("couldn't find expected hash for: {:?}", (index as usize)..(index as usize+20)),
        }
    }
}

#[derive(Debug)]
struct Torrent {
    trackers: Vec<Tracker>,
    pieces_length: u32,
    pieces: AllHashes,
    info_bytes: Vec<u8>,
    peers: Vec<Peer>,
    length: u64,
    name: String,
    files: Vec<types::SizedFile>,

    // our state
    uploaded: u32,
    downloaded: u32
}

impl fmt::Display for Torrent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Trackers: {:#?}", self.trackers)?;
        writeln!(f, "pieces length: {}", self.pieces_length)?;
        writeln!(f, "info hash: {}", self.info_hash())?;
        writeln!(f, "name: {}", self.name)?;
        writeln!(f, "files: {:?}", self.files)?;
        writeln!(f, "peers: {:#?}", self.peers)?;
        writeln!(f, "downloaded: {}", self.downloaded)?;
        writeln!(f, "uploaded: {}", self.uploaded)
    }
}

impl Torrent {
    fn announce(&mut self, port: i64) -> Result<(), &'static str> {
        let info_hash = self.info_hash();
        let tracker = self.trackers.first_mut().expect("torrent missing tracker");
        let mut params = vec!(
            ("peer_id", CLIENT_ID.to_string()),
            ("port", port.to_string()),
            ("uploaded", "0".to_string()),
            ("downloaded", "0".to_string()),
            ("compact", "1".to_string()),
            ("event", "paused".to_string()),
            ("numwant", 50.to_string()),
            ("left", self.pieces_length.to_string()),
        );
        if let Some(known_tracker_id) = &tracker.tracker_id {
            params.push(("trackerid", known_tracker_id.clone()))        }
        let announce = Url::parse_with_params(
            format!("{}/announce?info_hash={}",
                tracker.announce_url,
                info_hash
            ).as_str(),
            params
        ).expect("announce url parsed");
        println!("announce url: {}", announce);
        let mut res = match reqwest::blocking::get(announce) {
            Ok(res) => res,
            Err(e) => {
                println!("{}", e);
                return Err("reqwset get error")
            }
        };
        let mut body = vec!();
        match res.read_to_end(&mut body) {
            Ok(_) => (),
            Err(_) => return Err("error on res.read_to_end")
        };

        println!("Status: {}", res.status());
        let bt = match mescal::parse_bytes(&mut body.iter().peekable()) {
            Ok(bt) => bt,
            Err(e) => {
                println!("bencode parse error: {:?}", e);
                return Err("bencode parse error")
            }
        };

        print!("Bencode response: {}", bt);

        let response: HashMap<String, BencodeItem> = if let BencodeItem::Dict(d) = bt {
            d.into_iter().collect()
        } else {
            return Err("respone not dict")
        };

        tracker.interval = match response.get("interval") {
            Some(BencodeItem::Int(i)) => Some(*i),
            Some(_) => return Err("interval not string"),
            None => return Err("interval missing")
        };

        // if trackerid missing, don't erase one we may have
        match response.get("trackerid") {
            Some(BencodeItem::String(s)) => match s.try_into() {
                Ok(ss) => tracker.tracker_id = Some(ss),
                Err(_) => return Err("trackerid parse err")
            },
            Some(_) => return Err("trackerid not string"),
            None => ()
        };

        let peers = match response.get("peers") {
            Some(BencodeItem::String(p)) => p,
            Some(_) => return Err("expected peers bytestring"),
            None => {
                match response.get("peers6") {
                    Some(BencodeItem::String(p)) => p,
                    Some(_) => return Err("expected peers bytestring"),
                    None => return Err("missing peers")
                }
            }
        };

        for i in (0..peers.bytes.len()).step_by(6) {
            let peer = &peers.bytes[i..i+6];
            self.peers.push(Peer::new(peer.try_into().expect("wrong addr size")));
        }

        Ok(())
    }

    fn connect_peer(&self, peer: &Peer) -> Result<(), &'static str> {
        let mut our_state = PeerState::ChokingNotInterested;
        let mut their_state = PeerState::ChokingNotInterested;
        let download_algorithm = SequentialDownload {};

        let ip = IpAddr::V4(Ipv4Addr::new(peer.addr[0], peer.addr[1], peer.addr[2], peer.addr[3]));
        let port = ((peer.addr[4] as u16) << 8) | peer.addr[5] as u16;
        let addr = SocketAddr::new(ip, port);
        println!("handshake with {}", addr);
        let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                println!("connection error: {}", e);
                return Err("failed to connect")
            }
        };
        let mut message = vec!();

        let pstrlen = 19;
        println!("pstrlen: {:x?}", pstrlen);

        let mut pstr = "BitTorrent protocol".as_bytes().to_vec();
        println!("pstr: {:x?}", pstr);

        let mut reserved = [0, 0, 0, 0, 0, 0, 0, 0].to_vec();
        println!("reserved: {:x?}", reserved);

        let info_hash_bytes = self.info_hash_bytes();

        let mut info_hash = info_hash_bytes.to_vec();
        println!("info_hash: {:x?}", info_hash);

        let mut peer_id = CLIENT_ID.as_bytes().to_vec();
        println!("peer_id: {:x?}", peer_id);

        message.push(pstrlen);
        message.append(&mut pstr);
        message.append(&mut reserved);
        message.append(&mut info_hash);
        message.append(&mut peer_id);

        println!("handshake message - client: {:x?}", message);
        println!("handshake message length: {}", message.len());

        match stream.write(&mut message) {
            Ok(b) => println!("handshake wrote bytes: {}", b),
            Err(e) => panic!("handshake write err: {}", e)
        };

        let mut buff: [u8; 68] = [0; 68]; // expecting 68 for handshake, 49+len(pstr) assuming pstr="BitTorrent protocol"
        // read handshake response
        match stream.read(&mut buff) {
            Ok(n) => println!("read {} bytes: {:x?}", n, buff),
            Err(e) => println!("error reading bytes: {}", e),
        };
        let other_pstrlen: usize = buff[0].into();
        let other_info_hash = buff.get(1+other_pstrlen+8..1+other_pstrlen+8+20).expect("peer sends info hash");

        println!("handshake response:");
        println!("pstrlen: {}", buff[0]);
        println!("pstr: {:x?}", buff.get(1..other_pstrlen));
        println!("reserved: {:x?}", buff.get(1+other_pstrlen..1+other_pstrlen+8));
        println!("info_hash: {:x?}", other_info_hash);
        println!("peer_id: {:x?}", from_utf8(buff.get(1+other_pstrlen+8+20..1+other_pstrlen+8+20+20).unwrap()));

        let info_hash_slice = &info_hash_bytes[..];
        let other_info_hash_slice = &other_info_hash[..];
        println!("ours: {:?}, theirs: {:?}", info_hash_slice, other_info_hash_slice);

        if info_hash_slice != other_info_hash_slice {
            stream.shutdown(Shutdown::Both).expect("shutdown");
            return Err("info_hashes do not match")
        }

        let interested_message = Message::Interested.to_bytes();
        println!("sending interested message: {:x?}", interested_message);
        match stream.write(&interested_message) {
            Ok(b) => println!("wrote interested message, b={}", b),
            Err(e) => {
                println!("err writing interested message, {}", e);
                stream.shutdown(Shutdown::Both).expect("shutdown");
                return Err("err writing interested")
            }
        }
        our_state = PeerState::ChokingInterested;

        let mut data: InMemoryData = InMemoryData::new(self.pieces.len() as u32 / 20);

        let mut block_index_in_progress: Option<PieceInProgress> = None;
        // after reading from the stream, if we determine that we just finished a block, send a "have" message.
        // since we know that what we just read was part of an in-progress block, there's no need
        // to parse that set of bytes as a message, so we "skip it".
        let mut skip_parsing;
        let mut read_zero_counter = 0;
        let mut piece_completed_index: Option<u32>;
        loop {
            skip_parsing = false;
            piece_completed_index = None;
            let mut buff = [0; 32768 * 2];
            let bytes_read = match stream.read(&mut buff) {
                Ok(n) => {
                    println!("\n-- read {} bytes", n);
                    n
                    // for i in 0..n {
                    //     println!("byte {}: {:b} - {}", i, buff[i], buff[i])
                    // }
                },
                Err(e) => panic!("error reading bytes: {}", e),
            };
            if bytes_read == 0 {
                read_zero_counter += 1;
                println!("read_zero_counter = {}", read_zero_counter);
                if read_zero_counter > 5 {
                    println!("giving up");
                    stream.shutdown(Shutdown::Both).expect("shutdown");
                    break;
                }
                continue;
            }
            println!("first 20 bytes: {:x?}", buff.get(..20));
            match &block_index_in_progress {
                Some(pi) => {
                    println!("piece in progress, appending...");
                    data.append_to_piece(pi.index, buff.get(0..bytes_read).unwrap().to_vec())?;

                    if bytes_read as u32 == pi.missing_bytes {
                        println!("got the rest of missing bytes!");
                        if self.pieces.hash_for_index(pi.index) == data.get_piece(pi.index).unwrap().hash() {
                            data.mark_piece_completed(pi.index)?;
                            piece_completed_index = Some(pi.index);
                        }

                        block_index_in_progress = None;
                        skip_parsing = true;

                    } else {
                        println!("still have bytes missing");
                        continue;
                    }
                },
                None => println!("no piece in progress; parsing as regular message"),
            }
            if !skip_parsing {
                let parsed = match Message::from_bytes(&buff, bytes_read as u32) {
                    Ok(m) => m,
                    Err(e) => return Err(e),
                };
                println!("got message: {}", parsed);
                match parsed {
                    Message::KeepAlive => {
                        println!("ignoring keep-alive")
                    },
                    Message::Choke => {
                        their_state = match their_state {
                            PeerState::NotChokingNotInterested => PeerState::ChokingNotInterested,
                            PeerState::NotChokingInterested => PeerState::ChokingInterested,
                            PeerState::ChokingNotInterested => PeerState::ChokingNotInterested,
                            PeerState::ChokingInterested => PeerState::ChokingInterested,
                        }
                    },
                    Message::Unchoke => {
                        their_state = match their_state {
                            PeerState::NotChokingNotInterested => PeerState::NotChokingNotInterested,
                            PeerState::NotChokingInterested => PeerState::NotChokingInterested,
                            PeerState::ChokingNotInterested => PeerState::NotChokingNotInterested,
                            PeerState::ChokingInterested => PeerState::NotChokingInterested,
                        }
                    },
                    Message::Interested => {
                        their_state = match their_state {
                            PeerState::NotChokingNotInterested => PeerState::NotChokingInterested,
                            PeerState::NotChokingInterested => PeerState::NotChokingInterested,
                            PeerState::ChokingNotInterested => PeerState::ChokingInterested,
                            PeerState::ChokingInterested => PeerState::ChokingInterested,
                        }
                    },
                    Message::NotInterested => {
                        their_state = match their_state {
                            PeerState::NotChokingNotInterested => PeerState::NotChokingNotInterested,
                            PeerState::NotChokingInterested => PeerState::NotChokingNotInterested,
                            PeerState::ChokingNotInterested => PeerState::ChokingNotInterested,
                            PeerState::ChokingInterested => PeerState::ChokingNotInterested,
                        }
                    },
                    Message::Have { piece_index } => {
                        println!("ignoring have msg - piece_index={}", piece_index)
                    },
                    Message::Bitfield { bitfield } => {
                        let num_of_pieces = self.pieces.len() / 20; // pieces is concat of 20-byte hashes for each piece
                        let mut has_pieces = 0;
                        println!("there are {} pieces", num_of_pieces);
                        for i in 0..num_of_pieces - 1 {
                            println!("checking piece {}", i);
                            let nth = i % 8;
                            println!("bitmask {:08b}", 128 >> nth);
                            let byte_num = i / 8;
                            println!("byte number: {}", byte_num);
                            println!("{:b} & {:08b}", bitfield[byte_num], 128 >> nth);
                            if bitfield[byte_num] & 128 >> nth != 0 {
                                println!("has piece {}", i);
                                has_pieces += 1;
                            } else {
                                println!("missing piece {}", i);
                            }
                        }
                        println!("has {} of {} pieces - {}%", has_pieces, num_of_pieces, (has_pieces / num_of_pieces) * 100);
                    },
                    Message::Request { index, begin, length } => {
                        println!("ignoring request msg - index={}, begin={}, length={}", index, begin, length)
                    },
                    Message::Piece { length, index, begin, block } => {
                        let block_len = block.len() as u32;
                        data.append_to_piece(index, block)?;
                        // 9 = size of piece message minus the block bytes
                        if (length - 9) > block_len {
                            println!("piece message incomplete. expected length={}, got length={}, missing bytes={}", length - 9, block_len, length - 9 - block_len);
                            block_index_in_progress = Some(PieceInProgress { index, missing_bytes: length - 9 - block_len });
                        } else {
                            println!("piece message appears complete: length-9={}, block len={}", length - 9, block_len);

                            if self.pieces.hash_for_index(index) == data.get_piece(index).unwrap().hash() {
                                data.mark_piece_completed(index);
                                piece_completed_index = Some(index);
                                println!("piece completed at index={}", index);
                            }
                            block_index_in_progress = None;
                        }
                    },
                    Message::Cancel { index, begin, length } => {
                        println!("ignoring cancel msg - index={}, begin={}, length={}", index, begin, length)
                    },
                    Message::Port { listen_port } => {
                        println!("ignoring port msg - port={}", listen_port)
                    },
                }
            }

            println!("our state: {:?}, their state: {:?}", our_state, their_state);

            if block_index_in_progress.is_some() {
                println!("Not sending follow-up message since piece in progress");
                continue;
            }

            match their_state {
                PeerState::NotChokingNotInterested | PeerState::NotChokingInterested => {
                    match piece_completed_index {
                        Some(pi) => {
                            let have_msg = Message::Have { piece_index: pi };
                            println!("sending have message: {}", have_msg);
                            let have_msg = have_msg.to_bytes();
                            match stream.write(&have_msg) {
                                Ok(b) => println!("wrote have message, b={}", b),
                                Err(e) => {
                                    println!("err writing have message, {}", e);
                                    stream.shutdown(Shutdown::Both).expect("shutdown");
                                    return Err("err writing have")
                                }
                            }
                        },
                        None => {},
                    }
                    match download_algorithm.next_to_request(&data) {
                        Some(rp) => {
                            println!("requesting piece part={:?}", rp);
                            let num_of_pieces = self.pieces.len() as u32 / 20;
                            let request_msg = if rp.piece_index != (num_of_pieces - 1) {
                                Message::Request {
                                    index: rp.piece_index, begin: rp.offset, length: 16384 // 16kb
                                }
                            } else {
                                // last piece
                                let remaining_bytes = self.length as u32 - data.total_byte_len() as u32;
                                Message::Request {
                                    index: rp.piece_index, begin: rp.offset, length: remaining_bytes
                                }
                            };
                            println!("request_msg - {}", request_msg);
                            let request_msg = request_msg.to_bytes();
                            println!("sending request message: {:0x?}", request_msg);
                            match stream.write(&request_msg) {
                                Ok(b) => println!("wrote request message, b={}", b),
                                Err(e) => {
                                    println!("err writing request message, {}", e);
                                    stream.shutdown(Shutdown::Both).expect("shutdown");
                                    return Err("err writing requested")
                                }
                            }
                        },
                        None => {
                            println!("nothing to request. we're done!");
                            stream.shutdown(Shutdown::Both).expect("shutdown");
                            println!("torrent length={}, we have={}", self.length, data.total_byte_len());
                            data.flush(&self.files)?;
                            return Ok(())
                        }
                    }
                },
                _ => println!("not requesting, they're choking us")
            }
            println!("data len: {}", data.total_byte_len());
        }

        Ok(())
    }

    fn connect(&self) -> Result<(), &'static str> {
        for peer in &self.peers {
            match self.connect_peer(peer) {
                Ok(_) => println!("ok connect peer"),
                Err(e) => println!("err connect peer: {}", e),
            }
        }
        Ok(())
    }
}

impl TryFrom<BencodeItem> for Torrent {
    type Error = &'static str;

    fn try_from(value: BencodeItem) -> Result<Self, Self::Error> {
        let torrent = match value {
            BencodeItem::Dict(items) => items,
            _ => return Err("expected a dict")
        };
        let mut torrent_map: HashMap<String, BencodeItem> = HashMap::new();
        for (key, val) in torrent {
            torrent_map.insert(key, val);
        }
        let info = match torrent_map.get("info") {
            Some(i) => i,
            None => return Err("missing info")
        };
        let mut info_map: HashMap<&String, &BencodeItem> = HashMap::new();
        if let BencodeItem::Dict(d) = info {
            for (key, val) in d {
                info_map.insert(key, val);
            }
        } else {
            return Err("info not a dict")
        }
        let announce_url_bs: &ByteString = if torrent_map.contains_key("announce-list") {
            match torrent_map.get("announce-list") {
                Some(BencodeItem::List(sx)) => {
                    if sx.len() == 0 {
                        return Err("announce-list empty")
                    } else {
                        match &sx[0] {
                            BencodeItem::String(s) => s,
                            BencodeItem::List(sx2) => {
                                if sx2.len() == 0 {
                                    return Err("announce-list 2 empty")
                                } else {
                                    match &sx2[0] {
                                        BencodeItem::String(s2) => s2,
                                        _ => return Err("announce-list[0][0] not String")
                                    }
                                }
                            },
                            _ => return Err("announce-list[0] not String")
                        }
                    }
                },
                Some(_) => return Err("announce-list not List"),
                None => return Err("announce-list present but missing?"),
            }
        } else if torrent_map.contains_key("announce") {
            match torrent_map.get("announce") {
                Some(BencodeItem::String(s)) => s,
                Some(_) => return Err("announce present but not String type"),
                None => return Err("announce string present but missing?")
            }
        } else {
            return Err("Missing announce or announce-list")
        };
        let announce_url: String = match announce_url_bs.try_into() {
            Ok(s) => s,
            Err(_) => return Err("announce_url_bs not string"),
        };
        let tracker_id = match torrent_map.get("trackerid") {
            Some(BencodeItem::String(s)) => match s.try_into() {
                Ok(s) => Some(s),
                Err(_) => return Err("trackerid stringify err"),
            },
            Some(_) => return Err("trackerid not string"),
            None => None
        };
        let pieces_length = match info_map.get(&"piece length".to_string()) {
            Some(BencodeItem::Int(i)) => *i,
            Some(_) => return Err("pieces length not int"),
            None => return Err("missing pieces length")
        };

        let pieces = match info_map.get(&"pieces".to_string()) {
            Some(BencodeItem::String(bs)) => bs.bytes.clone(),
            Some(_) => return Err("pieces not String"),
            None => return Err("missing pieces"),
        };

        let length = match info_map.get(&"length".to_string()) {
            Some(BencodeItem::Int(i)) => Some(*i),
            Some(_) => return Err("length not int"),
            None => {
                println!("Missing length");
                None
            }
        };

        let files: Option<Vec<types::SizedFile>> = match info_map.get(&"files".to_string()) {
            Some(BencodeItem::List(fx)) => {
                let mut files = vec!();
                for f in fx {
                    let mut length: Option<u64> = None;
                    let mut path: Option<String> = None;
                    match f {
                        BencodeItem::Dict(fd) => {
                            for (k, v) in fd {
                                if k.eq("length") {
                                    match v {
                                        BencodeItem::Int(i) => {
                                            length = Some(*i as u64);
                                        },
                                        _ => return Err("length part of files dict incorrect type")
                                    }
                                }
                                if k.eq("path") {
                                    match v {
                                        BencodeItem::List(px) => {
                                            if px.len() > 1 {
                                                panic!("multiple paths")
                                            }
                                            match &px[0] {
                                                BencodeItem::String(p) => {
                                                    path = Some(from_utf8(p.bytes.as_slice()).unwrap().to_string());
                                                },
                                                _ => return Err("path part of files list incorrect type")

                                            }
                                        },
                                        _ => return Err("path part of files list incorrect type"),
                                    }
                                }
                            }
                        },
                        _ => return Err("files list item not dict")
                    }
                    match (length, path) {
                        (Some(l), Some(p)) => files.push(types::SizedFile { length: l, name: p }),
                        _ => return Err("failed to get length or path for a file")
                    }
                }
                Some(files)
            },
            Some(_) => return Err("files not dict"),
            None => None,
        };

        let name = match info_map.get(&"name".to_string()) {
            Some(BencodeItem::String(bs)) => from_utf8(bs.bytes.as_slice()).unwrap().to_string(),
            Some(_) => return Err("name not String"),
            None => return Err("missing name")
        };

        let (total_length, files) = match (length, files) {
            (None, None) => return Err("no length or files"),
            (None, Some(fx)) => {
                let mut l = 0;
                for f in &fx {
                    l += f.length;
                }
                (l, fx)
            },
            (Some(l), None) => {
                (l as u64, vec!(types::SizedFile { name: name.clone(), length: l as u64 }))
            },
            (Some(_), Some(_)) => return Err("both length and files"),
        };

        // trackerid
        // interval
        // mininterval

        Ok(Torrent {
            trackers: vec!(Tracker { announce_url, tracker_id, interval: None, min_interval: None }),
            pieces_length: pieces_length as u32, // overflow?
            pieces: AllHashes::new(pieces),
            name,
            files,
            length: total_length,
            info_bytes: info.as_bytes(),
            peers: vec!(),
            uploaded: 0,
            downloaded: 0
        })
    }
}

impl InfoHash for Torrent {
    fn info_hash(&self) -> String {
        byte_serialize(&self.info_hash_bytes()).collect()
    }

    fn info_hash_bytes(&self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(&self.info_bytes);
        hasher.finalize().try_into().expect("hashed")
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let bt = mescal::open(file_path).expect("parsed .torrent");
    println!("Bencode:");
    println!("{}", bt);

    let mut torrent: Torrent = bt.try_into()?;
    println!("Torrent:");
    println!("{}", torrent);

    torrent.announce(5035)?;

    println!("got peers:");
    println!("{:?}", torrent.peers);

    match torrent.connect() {
        Ok(_) => println!("successfully finished with peer"),
        Err(e) => println!("error communicating with peer: {}", e),
    }

    Ok(())
}
