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

    fn handshake(&self, torrent: &Torrent) -> Result<(), &'static str> {
        let ip = IpAddr::V4(Ipv4Addr::new(self.addr[0], self.addr[1], self.addr[2], self.addr[3]));
        let port = ((self.addr[4] as u16) << 8) | self.addr[5] as u16;
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

        let mut info_hash = torrent.info_hash_bytes().to_vec();
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

        let mut res: Vec<u8> = vec!();
        match stream.read_to_end(&mut res) {
            Ok(b) => println!("handshake read bytes: {}", b),
            Err(e) => panic!("handshake read err: {}", e),
        };

        println!("read response: {:x?}", res);

        stream.shutdown(Shutdown::Both).expect("shutdown");
        Ok(())
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
        let announce_url: String = match torrent_map.get("announce") {
            Some(BencodeItem::String(s)) => match s.try_into() {
                Ok(s) => s,
                Err(_) => return Err("announce stringify err"),
            },
            Some(_) => return Err("announce not string"),
            None => return Err("announce missing")
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

        // trackerid
        // interval
        // mininterval

        Ok(Torrent {
            trackers: vec!(Tracker { announce_url, tracker_id, interval: None, min_interval: None }),
            pieces_length,
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

    for peer in &torrent.peers {
        match peer.handshake(&torrent) {
            Ok(_) => println!("shook hands!"),
            Err(e) => println!("failed to shake hands: {}", e),
        }
    }

    Ok(())
}
