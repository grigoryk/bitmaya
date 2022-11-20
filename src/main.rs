use std::time::Duration;
use std::{env, collections::HashMap};
use form_urlencoded::byte_serialize;
use mescal::{open, parse_bytes, BencodeItem, AsBencodeBytes, BencodeError};
use sha1::{Sha1, Digest};
use std::error::Error;
use std::io::Read;
use url::Url;
use std::net::TcpStream;

#[derive(Debug)]
struct Peer {
    addr: [u8; 6]
}

trait InfoHash {
    fn info_hash(&self) -> String;
}

#[derive(Debug)]
struct Torrent {
    announce_url: String,
    pieces_length: i64,
    info_bytes: Vec<u8>,
    peers: Vec<Peer>,
}

impl Torrent {
    fn announce(&mut self) -> Result<(), &'static str> {
        let announce = Url::parse_with_params(format!("{}{}?info_hash={}", self.announce_url, "/announce", self.info_hash()).as_str(), &[
            ("peer_id", "-DE211s-pMaStd.(9qxs".to_string()),
            ("port", 5035.to_string()),
            ("uploaded", "0".to_string()),
            ("downloaded", "0".to_string()),
            ("compact", "1".to_string()),
            ("event", "paused".to_string()),
            ("numwant", 50.to_string()),
            ("left", self.pieces_length.to_string()),
        ]).expect("parsed");
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
        let bt = match parse_bytes(&mut body.iter().peekable()) {
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

        let peers = match response.get("peers6") {
            Some(BencodeItem::String(p)) => p,
            Some(_) => return Err("expected peers bytestring"),
            None => return Err("missing peers")
        };

        for i in (0..peers.bytes.len()).step_by(6) {
            let peer = &peers.bytes[i..i+6];
            self.peers.push(Peer { addr: peer.try_into().expect("wrong addr size") });
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
                Err(_) => return Err("announce stringify err:"),
            },
            Some(_) => return Err("announce not string"),
            None => return Err("announce missing")
        };
        let pieces_length = match info_map.get(&"piece length".to_string()) {
            Some(BencodeItem::Int(i)) => *i,
            Some(_) => return Err("pieces length not int"),
            None => return Err("missing pieces length")
        };
        Ok(Torrent {
            announce_url,
            pieces_length,
            info_bytes: info.as_bytes(),
            peers: vec!()
        })
    }
}

impl InfoHash for Torrent {
    fn info_hash(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(&self.info_bytes);
        let info_hash = hasher.finalize();
        byte_serialize(&info_hash).collect()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let bt = open(file_path).expect("parsed .torrent");
    println!("Bencode:");
    println!("{}", bt);

    let mut torrent: Torrent = bt.try_into()?;
    println!("Torrent:");
    println!("{:?}", torrent);

    torrent.announce()?;

    println!("got peers:");
    println!("{:?}", torrent.peers);

    // TcpStream::connect_timeout(addr, Duration::from_secs(10));

    Ok(())
}
