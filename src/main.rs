use std::io;
use std::time::Duration;
use std::{env, collections::HashMap};
use form_urlencoded::byte_serialize;
use mescal::{BencodeItem, AsBencodeBytes, ByteString};
use sha1::{Sha1, Digest};
use uuid::Uuid;
use std::error::Error;
use std::io::{Read, Write};
use url::Url;
use std::net::{TcpStream as StdTcpStream, SocketAddr, Shutdown, IpAddr, Ipv4Addr};
use std::fmt;
use std::str::from_utf8;
use mio::Interest;
use mio::net::TcpStream;

mod types;
mod serialization;
mod message;
mod data_buffers;
mod poller;

use crate::poller::Poller;
use crate::message::Message;
use crate::data_buffers::{DataBuffer, InMemoryData, SequentialDownload, DownloadStrategy};

use crate::data_buffers::PieceInProgress;

const CLIENT_ID: &str = "-BM0010-123456789012";

#[derive(Debug, Copy, Clone, PartialEq)]
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
    downloaded: u32,
    data: InMemoryData,
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

    // state machine loop:
    // - check ready connection
    // - get it back
    // - retrieve its state
    // - process it until it's blocked or done

    // functions so far are written assuming an async support...

    // list of peer network operations:
    // - "peer loop"
    // -- shared state - torrent data
    // -- need to be able to resume where left off after being blocked by io
    // -- resume is: where + what

    fn connect_peer(&self, stream: &mut TcpStream) -> Result<(), &'static str> {
        // -- SETUP
        let mut our_state = PeerState::ChokingNotInterested;
        let mut their_state = PeerState::ChokingNotInterested;
        let download_algorithm = SequentialDownload {};

        // -- HANDSHAKE SEND
        let info_hash_bytes = self.info_hash_bytes();
        let message = handshake(&info_hash_bytes);
        println!("handshake message - client: {:x?}", message);
        println!("handshake message length: {}", message.len());

        match stream.write(&message) {
            Ok(b) => println!("handshake wrote bytes: {}", b),
            Err(e) => panic!("handshake write err: {}", e)
        };

        // -- HANDSHAKE RECEIVE
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

        // -- INTERESTED
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

        let mut data = InMemoryData::new(self.pieces.len() as u32 / 20);

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

                    if bytes_read == pi.missing_bytes {
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
                let parsed = match Message::from_bytes(&buff, bytes_read) {
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
                        let block_len = block.len();
                        data.append_to_piece(index, block)?;
                        // 9 = size of piece message minus the block bytes
                        if (length - 9) > block_len {
                            println!("piece message incomplete. expected length={}, got length={}, missing bytes={}", length - 9, block_len, length - 9 - block_len);
                            block_index_in_progress = Some(PieceInProgress { index, missing_bytes: length - 9 - block_len });
                        } else {
                            println!("piece message appears complete: length-9={}, block len={}", length - 9, block_len);

                            if self.pieces.hash_for_index(index) == data.get_piece(index).unwrap().hash() {
                                data.mark_piece_completed(index)?;
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
}

fn peer_to_stream(peer: &Peer) -> Result<TcpStream, i32> {
    let ip = IpAddr::V4(Ipv4Addr::new(peer.addr[0], peer.addr[1], peer.addr[2], peer.addr[3]));
    let port = ((peer.addr[4] as u16) << 8) | peer.addr[5] as u16;
    let addr = SocketAddr::new(ip, port);
    println!("handshake with {}", addr);
    let std_stream = match StdTcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => {
            println!("connection error: {}", e);
            return Err(1)
        }
    };
    if let Err(e) = std_stream.set_nonblocking(true) {
        println!("connection error: {}", e);
        return Err(2)
    }
    Ok(TcpStream::from_std(std_stream))
}

fn handshake(info_hash_bytes: &[u8; 20]) -> Vec<u8> {
    let mut message = vec!();

    let pstrlen = 19;
    println!("pstrlen: {:x?}", pstrlen);

    let mut pstr = "BitTorrent protocol".as_bytes().to_vec();
    println!("pstr: {:x?}", pstr);

    let mut reserved = [0, 0, 0, 0, 0, 0, 0, 0].to_vec();
    println!("reserved: {:x?}", reserved);

    let mut info_hash = info_hash_bytes.to_vec();
    println!("info_hash: {:x?}", info_hash);

    let mut peer_id = CLIENT_ID.as_bytes().to_vec();
    println!("peer_id: {:x?}", peer_id);

    message.push(pstrlen);
    message.append(&mut pstr);
    message.append(&mut reserved);
    message.append(&mut info_hash);
    message.append(&mut peer_id);

    message
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
            downloaded: 0,
            data: InMemoryData::new(pieces_length as u32 / 20)
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

#[derive(Debug)]
enum PeerConnectionState {
    Start { info_hash: [u8; 20] },
    HandshakeSending { message: Vec<u8> },
    HandshakeReceiving {
        buff: [u8; 68] // expecting 68 for handshake, 49+len(pstr) assuming pstr="BitTorrent protocol"
    },
    InterestedSending { message: Vec<u8> },
    MessageRead {
        attempt: i8,
        buff: [u8; 65536]
    },
    MessageParse {
        bytes_read: usize,
        buff: [u8; 65536],
        their_state: PeerState,
    },
    MessagePieceReceive {
        attempt: i8,
        index: u32,
        missing_bytes: usize,
        buff: [u8; 65536],
        their_state: PeerState,
    },
    SendHave { index: u32 },
    SendRequestPiece,

    // terminal states
    MismatchedInfoHashes,
    GaveUpOnPeer,
}

impl fmt::Display for PeerConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PeerConnectionState::Start { .. } => {
                writeln!(f, "State::Start info_hash=[..]")
            }
            PeerConnectionState::HandshakeSending { .. } => {
                writeln!(f, "State::HandshakeSending message=[..]")
            }
            PeerConnectionState::HandshakeReceiving { .. } => {
                writeln!(f, "State::HandshakeReceiving buff=[..]")
            }
            PeerConnectionState::InterestedSending { .. } => {
                writeln!(f, "State::InterestedSending")
            }
            PeerConnectionState::MessageRead { attempt, .. } => {
                writeln!(f, "State::MessageRead attempt={}, buff=[..]", attempt)
            }
            PeerConnectionState::MessageParse { bytes_read, their_state, .. } => {
                writeln!(f, "State::MessageParse bytes_read={} their_state={:?}, buff=[..]", bytes_read, their_state)
            }
            PeerConnectionState::MessagePieceReceive { attempt, index, missing_bytes, buff, their_state } => {
                writeln!(f, "State::MessagePieceReceive attempt={} index={} missing_bytes={}, buff=[..], their_state={:?}", attempt, index, missing_bytes, their_state)
            }
            PeerConnectionState::SendHave { index } => {
                writeln!(f, "State::SendHave index={}", index)
            }
            PeerConnectionState::SendRequestPiece => {
                writeln!(f, "State::SendRequestPiece")
            }
            PeerConnectionState::MismatchedInfoHashes => {
                writeln!(f, "State::MismatchedInfoHashes")
            }
            PeerConnectionState::GaveUpOnPeer => {
                writeln!(f, "State::GaveUpOnPeer")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum PeerEvent {
    BeginHandshake,
    HandshakeSendOk,
    HandshakeReceiveOk,
    MismatchedInfoHashes,
    InterestedSentOk,
    MessageReadOk { byte_count: usize },
    TheirStateChanged { state: PeerState },
    PieceCompleted { index: u32 },
    PieceIncomplete { index: u32, missing_bytes: usize },
    PieceCorrupt { index: u32 },
    GotBitfield { has_pieces: Vec<bool> },
    SendHaveOk,
    SendRequestPieceOk,
    HaveAllPieces,
    WouldBlock,
    CanRead,
    CanWrite,
    Continue,
    GiveUp,
    Retry
}

#[derive(Debug)]
struct PeerConnection {
    id: Uuid,
    event: Option<PeerEvent>,
    stream: TcpStream,
    peer_id: usize
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

    let mut poller = Poller::new()?;

    let mut connections: HashMap<usize, PeerConnection> = HashMap::new();
    let mut conn_states: HashMap<Uuid, PeerConnectionState> = HashMap::new();

    let info_hash = torrent.info_hash_bytes();

    for (peer_id, peer) in torrent.peers.as_slice().iter().enumerate() {
        let stream = match peer_to_stream(peer) {
            Ok(s) => Some(s),
            Err(e) => {
                println!("err peer to stream: {}", e);
                None
            }
        };
        if let Some(s) = stream {
            let conn_id = Uuid::new_v4();
            let conn_state = PeerConnectionState::Start { info_hash };
            connections.insert(peer_id, PeerConnection {
                id: conn_id.clone(),
                event: Some(PeerEvent::BeginHandshake),
                stream: s,
                peer_id
            });
            conn_states.insert(conn_id, conn_state);
        }
    }

    loop {
        for (_, conn) in &mut connections {
            // state machine consumes the state, so remove it to obtain ownership and then reinsert or insert new one
            if let Some(state) = conn_states.remove(&conn.id) {
                match state {
                    PeerConnectionState::GaveUpOnPeer => return Ok(()),
                    _ => {}
                }
                let mut next_state = if let Some(event) = &conn.event {
                    println!("got event {:?} for state {}", event, state);

                    let next_state = connection_state_machine(state, &event);
                    println!("next state {}", next_state);
                    next_state
                } else {
                    state
                };
                let next_event = state_effects(&mut poller, &mut torrent, conn, &mut next_state);
                match conn_states.insert(conn.id, next_state) {
                    Some(_) => panic!("duplicate state insertion for id={}, all states={:#?}", conn.id, conn_states),
                    None => {},
                }
                println!("ran state effects, next event {:?}", next_event);
                conn.event = next_event;
            } else {
                panic!("missing state for id={}; all states: {:#?}", conn.id, conn_states);
            }
        }

        println!("poll_wait");
        let event_count = poller.poll(Some(Duration::from_millis(1000)))?;
        println!("poll returned with events: {event_count}");

        for evt in poller.iter_events() {
            let peer_id = evt.key as usize;
            if let Some(conn) = connections.get_mut(&peer_id) {
                if conn.event == Some(PeerEvent::WouldBlock) || conn.event == None {
                    if evt.readable {
                        println!("poll_read_event");
                        conn.event = Some(PeerEvent::CanRead);
                    } else if evt.writable {
                        println!("poll_write_event");
                        conn.event = Some(PeerEvent::CanWrite);
                    }
                } else {
                    println!("ignoring poll event since conn.event={:?}", conn.event)
                }
            } else {
                panic!("unexpected peer_id from poll: {peer_id}");
            }
        }
    }
}

fn connection_state_machine(state: PeerConnectionState, event: &PeerEvent) -> PeerConnectionState {
    match state {
        PeerConnectionState::Start { info_hash } => match event {
            PeerEvent::BeginHandshake => PeerConnectionState::HandshakeSending { message: handshake(&info_hash) },
            _ => todo!()
        },
        PeerConnectionState::HandshakeSending { .. } => match event {
            PeerEvent::HandshakeSendOk => PeerConnectionState::HandshakeReceiving { buff: [0; 68] },
            PeerEvent::CanWrite | PeerEvent::WouldBlock => state,
            _ => todo!()
        },
        PeerConnectionState::HandshakeReceiving { .. } => match event {
            PeerEvent::MismatchedInfoHashes => PeerConnectionState::MismatchedInfoHashes,
            PeerEvent::HandshakeReceiveOk => PeerConnectionState::InterestedSending { message: Message::Interested.to_bytes() },
            PeerEvent::Continue | PeerEvent::CanRead | PeerEvent::WouldBlock => state,
            _ => todo!()
        },
        PeerConnectionState::InterestedSending { .. } => match event {
            PeerEvent::InterestedSentOk => PeerConnectionState::MessageRead {
                attempt: 0,
                buff: [0; 65536]
            },
            _ => todo!()
        },
        PeerConnectionState::MessageRead { attempt, buff } => match event {
            PeerEvent::MessageReadOk { byte_count } => PeerConnectionState::MessageParse {
                bytes_read: *byte_count,
                their_state: PeerState::ChokingNotInterested,
                buff
            },
            PeerEvent::Retry => PeerConnectionState::MessageRead { attempt: attempt + 1, buff },
            PeerEvent::GiveUp => PeerConnectionState::GaveUpOnPeer,
            PeerEvent::CanRead | PeerEvent::WouldBlock => state,
            _ => todo!()
        },
        PeerConnectionState::MessageParse { bytes_read, buff, their_state } => match event {
            PeerEvent::TheirStateChanged { state } => PeerConnectionState::SendRequestPiece,
            PeerEvent::PieceCompleted { index } => todo!(),
            PeerEvent::PieceIncomplete { index, missing_bytes } => PeerConnectionState::MessagePieceReceive {
                attempt: 0, index: *index, missing_bytes: *missing_bytes, buff, their_state
            },
            PeerEvent::PieceCorrupt { index } => todo!(),
            PeerEvent::GotBitfield { has_pieces } => PeerConnectionState::MessageRead { attempt: 0, buff: [0; 65536] },
            _ => todo!()
        },
        PeerConnectionState::MessagePieceReceive { attempt, missing_bytes, buff, their_state, .. } => match event {
            PeerEvent::PieceCompleted { index } => PeerConnectionState::SendHave { index: *index },
            PeerEvent::PieceCorrupt { .. } => todo!(),
            PeerEvent::CanRead => state,
            _ => todo!()
        },
        PeerConnectionState::SendHave { index } => match event {
            PeerEvent::SendHaveOk => PeerConnectionState::SendRequestPiece,
            _ => todo!()
        }
        PeerConnectionState::SendRequestPiece => match event {
            PeerEvent::SendRequestPieceOk => PeerConnectionState::MessageRead { attempt: 0, buff: [0; 65536] },
            PeerEvent::CanWrite | PeerEvent::WouldBlock => state,
            PeerEvent::HaveAllPieces => PeerConnectionState::GaveUpOnPeer, // TODO
            _ => todo!()
        },

        // terminal states ignore all events, can't transition out of them
        PeerConnectionState::MismatchedInfoHashes => state,
        PeerConnectionState::GaveUpOnPeer => state

    }
}

fn state_effects(poller: &mut Poller, torrent: &mut Torrent, conn: &mut PeerConnection, state: &mut PeerConnectionState) -> Option<PeerEvent> {
    match state {
        PeerConnectionState::HandshakeSending { message } => match conn.event {
            Some(PeerEvent::BeginHandshake) => {
                match buffer_to_stream(&mut conn.stream, &message) {
                    StreamResult::Done => {
                        deregister_stream(poller, &mut conn.stream).expect("poller_delete");
                        Some(PeerEvent::HandshakeSendOk)
                    },
                    StreamResult::Partial(c) => panic!("partial write during handshake: {c} of {}", message.len()),
                    StreamResult::WouldBlock => Some(would_block_write(poller, &mut conn.stream, conn.peer_id as u64))
                }
            },
            Some(PeerEvent::CanWrite) => todo!("HandshakeSending:CanWrite handling"),
            _ => None,
        },
        PeerConnectionState::HandshakeReceiving { buff } => match conn.event {
            Some(PeerEvent::HandshakeSendOk) | Some(PeerEvent::Continue) | Some(PeerEvent::CanRead) => {
                match stream_to_buffer(&mut conn.stream, buff.len(), buff) {
                    StreamResult::Done => {
                        deregister_stream(poller, &mut conn.stream).expect("poller_delete");
                        let other_pstrlen: usize = buff[0].into();
                        let other_info_hash = buff.get(1+other_pstrlen+8..1+other_pstrlen+8+20).expect("peer sends info hash");

                        println!("handshake response:");
                        println!("pstrlen: {}", buff[0]);
                        println!("pstr: {:x?}", buff.get(1..other_pstrlen));
                        println!("reserved: {:x?}", buff.get(1+other_pstrlen..1+other_pstrlen+8));
                        println!("info_hash: {:x?}", other_info_hash);
                        println!("peer_id: {:x?}", from_utf8(buff.get(1+other_pstrlen+8+20..1+other_pstrlen+8+20+20).unwrap()));

                        let info_hash_slice = &torrent.info_hash_bytes()[..];
                        let other_info_hash_slice = &other_info_hash[..];
                        println!("ours: {:?}, theirs: {:?}", info_hash_slice, other_info_hash_slice);

                        if info_hash_slice != other_info_hash_slice {
                            conn.stream.shutdown(Shutdown::Both).expect("shutdown");
                            Some(PeerEvent::MismatchedInfoHashes)
                        } else {
                            Some(PeerEvent::HandshakeReceiveOk)
                        }
                    },
                    StreamResult::Partial(_) => Some(PeerEvent::Continue),
                    StreamResult::WouldBlock => Some(would_block_read(poller, &mut conn.stream, conn.peer_id as u64))
                }
            },
            _ => None
        },
        PeerConnectionState::InterestedSending { message } => match conn.event {
            Some(PeerEvent::HandshakeReceiveOk) | Some(PeerEvent::Continue) | Some(PeerEvent::CanWrite) => {
                println!("sending interested message: {:x?}", message);
                match buffer_to_stream(&mut conn.stream, &message) {
                    StreamResult::Done => {
                        deregister_stream(poller, &mut conn.stream).expect("poller_delete");
                        Some(PeerEvent::InterestedSentOk)
                    },
                    StreamResult::Partial(_) => todo!(),
                    StreamResult::WouldBlock => Some(would_block_write(poller, &mut conn.stream, conn.peer_id as u64))
                }
            },
            _ => todo!()
        },
        PeerConnectionState::MessageRead { attempt, buff } => match conn.event {
            Some(PeerEvent::InterestedSentOk | PeerEvent::CanRead | PeerEvent::Retry | PeerEvent::GotBitfield { .. } | PeerEvent::SendRequestPieceOk) => {
                match stream_to_buffer_partial(&mut conn.stream, buff) {
                    StreamResultPartial::Read(c) => {
                        if c == 0 {
                            if *attempt > 5 {
                                deregister_stream(poller, &mut conn.stream).expect("poller_delete");
                                Some(PeerEvent::GiveUp)
                            } else {
                                Some(PeerEvent::Retry)
                            }
                        } else {
                            deregister_stream(poller, &mut conn.stream).expect("poller_delete");
                            Some(PeerEvent::MessageReadOk { byte_count: c })
                        }
                    },
                    StreamResultPartial::WouldBlock => Some(would_block_read(poller, &mut conn.stream, conn.peer_id as u64)),
                }
            },
            Some(PeerEvent::WouldBlock) => None,
            Some(_) => todo!("{:?}", conn.event),
            None => None

        },
        PeerConnectionState::MessageParse {
            bytes_read,
            their_state,
            buff } => match conn.event {
                Some(PeerEvent::MessageReadOk { byte_count }) => {
                    let parsed = match Message::from_bytes(buff, byte_count) {
                        Ok(m) => m,
                        Err(e) => todo!("bad message parse {}", e),
                    };
                    println!("got message: {}", parsed);
                    Some(match parsed {
                        Message::KeepAlive => todo!("keep-alive"),
                        Message::Choke => {
                            PeerEvent::TheirStateChanged { state: match their_state {
                                PeerState::NotChokingNotInterested => PeerState::ChokingNotInterested,
                                PeerState::NotChokingInterested => PeerState::ChokingInterested,
                                PeerState::ChokingNotInterested => PeerState::ChokingNotInterested,
                                PeerState::ChokingInterested => PeerState::ChokingInterested,
                            }}
                        },
                        Message::Unchoke => {
                            PeerEvent::TheirStateChanged { state: match their_state {
                                PeerState::NotChokingNotInterested => PeerState::NotChokingNotInterested,
                                PeerState::NotChokingInterested => PeerState::NotChokingInterested,
                                PeerState::ChokingNotInterested => PeerState::NotChokingNotInterested,
                                PeerState::ChokingInterested => PeerState::NotChokingInterested,
                            }}
                        },
                        Message::Interested => {
                            PeerEvent::TheirStateChanged { state: match their_state {
                                PeerState::NotChokingNotInterested => PeerState::NotChokingInterested,
                                PeerState::NotChokingInterested => PeerState::NotChokingInterested,
                                PeerState::ChokingNotInterested => PeerState::ChokingInterested,
                                PeerState::ChokingInterested => PeerState::ChokingInterested,
                            }}
                        },
                        Message::NotInterested => {
                            PeerEvent::TheirStateChanged { state: match their_state {
                                PeerState::NotChokingNotInterested => PeerState::NotChokingNotInterested,
                                PeerState::NotChokingInterested => PeerState::NotChokingNotInterested,
                                PeerState::ChokingNotInterested => PeerState::ChokingNotInterested,
                                PeerState::ChokingInterested => PeerState::ChokingNotInterested,
                            }}
                        },
                        Message::Have { piece_index } => todo!("have piece index {}", piece_index ),
                        Message::Bitfield { bitfield } => {
                            let num_of_pieces = torrent.pieces.len() / 20; // pieces is concat of 20-byte hashes for each piece
                            let mut has_pieces_vec = vec![];
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
                                    has_pieces_vec.push(true);
                                    has_pieces += 1;
                                } else {
                                    has_pieces_vec.push(false);
                                    println!("missing piece {}", i);
                                }
                            }
                            println!("has {} of {} pieces - {}%", has_pieces, num_of_pieces, (has_pieces / num_of_pieces) * 100);
                            PeerEvent::GotBitfield { has_pieces: has_pieces_vec }
                        },
                        Message::Request { index, begin, length } => todo!("ignoring request msg - index={}, begin={}, length={}", index, begin, length),
                        Message::Piece { length, index, begin, block } => {
                            let block_len = block.len();
                            torrent.data.append_to_piece(index, block).expect("data append worked");

                            // 9 = size of piece message minus the block bytes
                            if (length - 9) > byte_count {
                                println!("piece message incomplete. expected length={}, got length={}, missing bytes={}", length - 9, block_len, length - 9 - block_len);
                                PeerEvent::PieceIncomplete { index, missing_bytes: length - 9 - block_len }
                            } else {
                                println!("piece message appears complete: length-9={}, block len={}", length - 9, block_len);

                                if torrent.pieces.hash_for_index(index) == torrent.data.get_piece(index).unwrap().hash() {
                                    torrent.data.mark_piece_completed(index).expect("todo: mark_piece_complete failed");
                                    println!("piece completed at index={}", index);
                                    PeerEvent::PieceCompleted { index }
                                } else {
                                    PeerEvent::PieceCorrupt { index }
                                }
                            }
                        },
                        Message::Cancel { index, begin, length } => {
                            todo!("ignoring cancel msg - index={}, begin={}, length={}", index, begin, length)
                        },
                        Message::Port { listen_port } => {
                            todo!("ignoring port msg - port={}", listen_port)
                        },
                    })
                },
                _ => None,
        },
        PeerConnectionState::MessagePieceReceive {
            attempt,
            index,
            missing_bytes,
            buff,
            their_state } => match conn.event {
                    Some(PeerEvent::PieceIncomplete { .. } | PeerEvent::CanRead) => {
                    Some(match stream_to_buffer_partial(&mut conn.stream, buff) {
                        StreamResultPartial::Read(c) => {
                            if c == 0 {
                                if *attempt > 5 {
                                    deregister_stream(poller, &mut conn.stream).expect("poller_delete");
                                    PeerEvent::GiveUp
                                } else {
                                    PeerEvent::Retry
                                }
                            } else {
                                deregister_stream(poller, &mut conn.stream).expect("poller_delete");

                                println!("piece in progress, appending...");
                                torrent.data.append_to_piece(*index, buff.get(0..c).unwrap().to_vec()).expect("append_to_piece");

                                if c == *missing_bytes {
                                    println!("got the rest of missing bytes!");
                                    if torrent.pieces.hash_for_index(*index) == torrent.data.get_piece(*index).unwrap().hash() {
                                        torrent.data.mark_piece_completed(*index).expect("mark_piece_completed");
                                    }

                                    PeerEvent::PieceCompleted { index: *index }

                                } else {
                                    PeerEvent::PieceIncomplete { index: *index, missing_bytes: *missing_bytes - c }
                                }
                            }
                        },
                        StreamResultPartial::WouldBlock => would_block_read(poller, &mut conn.stream, conn.peer_id as u64),
                    })
                },
                _ => todo!()
        },
        PeerConnectionState::SendHave { index } => match conn.event {
            Some(PeerEvent::PieceCompleted { .. } | PeerEvent::CanWrite) => {
                let have_msg = Message::Have { piece_index: *index };
                println!("sending have message: {}", have_msg);
                let have_msg = have_msg.to_bytes();
                match buffer_to_stream(&mut conn.stream, &have_msg) {
                    StreamResult::Done => Some(PeerEvent::SendHaveOk),
                    StreamResult::Partial(_) => todo!(),
                    StreamResult::WouldBlock => Some(PeerEvent::WouldBlock),
                }
            },
            _ => todo!(),
        },
        PeerConnectionState::SendRequestPiece => match conn.event {
            Some(PeerEvent::TheirStateChanged { .. } | PeerEvent::SendHaveOk) => {
                let download_algorithm = SequentialDownload {};
                // TODO split "next_to_request" into its own state, this one should just own sending
                // TODO incorporate bitfield info
                match download_algorithm.next_to_request(&torrent.data) {
                    Some(rp) => {
                        println!("requesting piece part={:?}", rp);
                        let num_of_pieces = torrent.pieces.len() as u32 / 20;
                        let request_msg = if rp.piece_index != (num_of_pieces - 1) {
                            Message::Request {
                                index: rp.piece_index, begin: rp.offset, length: 16384 // 16kb
                            }
                        } else {
                            // last piece
                            let remaining_bytes = torrent.length as u32 - torrent.data.total_byte_len() as u32;
                            Message::Request {
                                index: rp.piece_index, begin: rp.offset, length: remaining_bytes
                            }
                        };
                        println!("request_msg - {}", request_msg);
                        let request_msg = request_msg.to_bytes();
                        println!("sending request message: {:0x?}", request_msg);
                        match buffer_to_stream(&mut conn.stream, &request_msg) {
                            StreamResult::Done => Some(PeerEvent::SendRequestPieceOk),
                            StreamResult::Partial(_) => todo!(),
                            StreamResult::WouldBlock => Some(would_block_read(poller, &mut conn.stream, conn.peer_id as u64)),
                        }
                    },
                    None => {
                        torrent.data.clone().flush(&torrent.files).expect("flush");
                        Some(PeerEvent::HaveAllPieces)
                    }
                }
            }
            _ => todo!()
        },
        PeerConnectionState::Start { .. } => None,
        PeerConnectionState::MismatchedInfoHashes => None,
        PeerConnectionState::GaveUpOnPeer => None,
    }
}

enum StreamResult {
    Done,
    Partial(usize),
    WouldBlock
}

enum StreamResultPartial {
    Read(usize),
    WouldBlock
}

fn buffer_to_stream(stream: &mut TcpStream, buffer: &[u8]) -> StreamResult {
    match stream.write(buffer) {
        Ok(c) => {
            if c == buffer.len() {
                StreamResult::Done
            } else {
                StreamResult::Partial(c)
            }
        },
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => StreamResult::WouldBlock,
        Err(e) => panic!("error writing to stream - {e}")
    }
}

fn stream_to_buffer(stream: &mut TcpStream, expected_bytes: usize, buffer: &mut [u8]) -> StreamResult {
    match stream.read(buffer) {
        Ok(c) => {
            if c == expected_bytes {
                StreamResult::Done
            } else {
                StreamResult::Partial(c)
            }
        },
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => StreamResult::WouldBlock,
        Err(e) => panic!("error reading from stream - {e}")
    }
}

fn stream_to_buffer_partial(stream: &mut TcpStream, buffer: &mut [u8]) -> StreamResultPartial {
    match stream.read(buffer) {
        Ok(c) => {
            StreamResultPartial::Read(c)
        },
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => StreamResultPartial::WouldBlock,
        Err(e) => panic!("error reading from stream - {e}")
    }
}

fn register_interest(poller: &mut Poller, stream: &mut TcpStream, key: u64, interest: Interest) -> io::Result<()> {
    poller.add_or_replace(stream, key, interest)
}

fn deregister_stream(poller: &mut Poller, stream: &mut TcpStream) -> io::Result<()> {
    poller.delete(stream)
}

fn would_block_write(poller: &mut Poller, stream: &mut TcpStream, peer: u64) -> PeerEvent {
    register_interest(poller, stream, peer, Interest::WRITABLE).expect("add fd worked");
    PeerEvent::WouldBlock
}

fn would_block_read(poller: &mut Poller, stream: &mut TcpStream, peer: u64) -> PeerEvent {
    register_interest(poller, stream, peer, Interest::READABLE).expect("add fd worked");
    PeerEvent::WouldBlock
}
