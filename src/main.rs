use std::time::Duration;
use std::{env, collections::HashMap};
use form_urlencoded::byte_serialize;
use mescal::{BencodeItem, AsBencodeBytes, ByteString};
use sha1::{Sha1, Digest};
use std::error::Error;
use std::io::{Read, Write};
use url::Url;
use std::net::{TcpStream, SocketAddr, Shutdown, IpAddr, Ipv4Addr};
use rand::thread_rng;
use rand::seq::SliceRandom;
use std::fmt;
use std::str::from_utf8;

mod message;

use message::Message;

const CLIENT_ID: &str = "-BM0010-123456789012";

#[derive(Debug)]
enum PeerState {
    NotChokingNotInterested,
    NotChokingInerested,
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
struct Torrent {
    trackers: Vec<Tracker>,
    pieces_length: i64,
    pieces: Vec<u8>,
    info_bytes: Vec<u8>,
    peers: Vec<Peer>,

    // our state
    uploaded: i64,
    downloaded: i64,
}

impl fmt::Display for Torrent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Trackers: {:#?}", self.trackers)?;
        writeln!(f, "pieces length: {}", self.pieces_length)?;
        writeln!(f, "info hash: {}", self.info_hash())?;
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
            return Err("info_hashes do not match")
        }

        let interested_message = Message::Interested.to_bytes();
        println!("sending interested message: {:x?}", interested_message);
        match stream.write(&interested_message) {
            Ok(b) => println!("wrote interested message, b={}", b),
            Err(e) => println!("err writing interested message, {}", e),
        }
        let mut buff = [0; 100];
        match stream.read(&mut buff) {
            Ok(n) => {
                println!("read {} bytes:", n);
                for i in 0..n {
                    println!("byte {}: {:b} - {}", i, buff[i], buff[i])
                }
            },
            Err(e) => println!("error reading bytes: {}", e),
        };
        let parsed = match Message::from_bytes(&buff) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };
        println!("got message: {:?}", parsed);
        match parsed {
            Message::KeepAlive => todo!(),
            Message::Choke => todo!(),
            Message::Unchoke => todo!(),
            Message::Interested => todo!(),
            Message::NotInterested => todo!(),
            Message::Have { piece_index } => todo!(),
            Message::Bitfield { bitfield } => {
                let num_of_pieces = self.pieces.len() / 20; // pieces is concat of 20-byte hashes for each piece
                let mut has_pieces = 0;
                println!("there are {} pieces", num_of_pieces);
                for i in 0..num_of_pieces {
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
            Message::Request { index, begin, length } => todo!(),
            Message::Piece { index, begin, block } => todo!(),
            Message::Cancel { index, begin, length } => todo!(),
            Message::Port { listen_port } => todo!(),
        }


        our_state = PeerState::ChokingInterested;

        stream.shutdown(Shutdown::Both).expect("shutdown");
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

        // trackerid
        // interval
        // mininterval

        Ok(Torrent {
            trackers: vec!(Tracker { announce_url, tracker_id, interval: None, min_interval: None }),
            pieces_length,
            pieces,
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
