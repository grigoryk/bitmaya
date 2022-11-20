use std::time::Duration;
use std::{env, collections::HashMap};
use form_urlencoded::byte_serialize;
use mescal::{open, parse_bytes, BencodeItem, AsBencodeBytes, BencodeError};
use sha1::{Sha1, Digest};
use std::error::Error;
use std::io::Read;
use url::Url;
use std::net::TcpStream;

trait InfoHash {
    fn info_hash(&self) -> String;
}

trait AsTorrent {
    fn to_torrent(self) -> Torrent;
}

#[derive(Debug)]
struct Torrent {
    announce_url: String,
    pieces_length: i64,
    info_bytes: Vec<u8>
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
            info_bytes: info.as_bytes()
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

struct Peer {

}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let bt = open(file_path).expect("parsed .torrent");
    println!("Bencode:");
    println!("{}", bt);

    let torrent: Torrent = bt.try_into().expect("torrent file");
    println!("Torrent:");
    println!("{:?}", torrent);

    let announce = Url::parse_with_params(format!("{}{}?info_hash={}", torrent.announce_url, "/announce", torrent.info_hash()).as_str(), &[
        ("peer_id", "-DE211s-pMaStd.(9qxs".to_string()),
        ("port", 5035.to_string()),
        ("uploaded", "0".to_string()),
        ("downloaded", "0".to_string()),
        ("compact", "1".to_string()),
        ("event", "paused".to_string()),
        ("numwant", 50.to_string()),
        ("left", torrent.pieces_length.to_string()),
    ]).expect("parsed");
    println!("announce url: {}", announce);
    let mut res = reqwest::blocking::get(announce)?;
    let mut body = vec!();
    res.read_to_end(&mut body)?;

    println!("Status: {}", res.status());
    // println!("Headers:\n{:#?}", res.headers());
    let bt = match parse_bytes(&mut body.iter().peekable()) {
        Ok(bt) => bt,
        Err(e) => panic!("bencode parse error: {:?}", e)
    };

    print!("Bencode response: {}", bt);

    let response: HashMap<String, BencodeItem> = if let BencodeItem::Dict(d) = bt {
        d.into_iter().collect()
    } else {
        panic!("3")
    };

    let peers = match response.get("peers6") {
        Some(BencodeItem::String(p)) => p,
        Some(_) => panic!("expected peers bytestring"),
        None => panic!("missing peers")
    };

    let mut peer_addresses = vec!();



    for i in (0..peers.bytes.len()).step_by(6) {
        let peer = &peers.bytes[i..i+6];
        peer_addresses.push(peer);
        println!("peer: {:?}", peer);
    }

    // TcpStream::connect_timeout(addr, Duration::from_secs(10));

    Ok(())
}
