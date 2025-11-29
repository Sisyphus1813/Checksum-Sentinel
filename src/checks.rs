// Copyright (C) 2025  Sisyphus1813
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::data_handling::{load_hashes, load_rules};
use digest::{Digest as DigestTrait, OutputSizeUser};
use generic_array::ArrayLength;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::ops::Add;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read},
    path::Path,
    sync::mpsc,
    thread,
};
use yara::Rules;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub hash_match: bool,
    pub yara_match: bool,
    pub yara_rules: Vec<String>,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

fn compute_hashes<P: AsRef<Path>>(path: P) -> io::Result<(String, String, String)> {
    let path = path.as_ref();
    let (tx_md5, rx_md5) = mpsc::channel::<Vec<u8>>();
    let (tx_sha1, rx_sha1) = mpsc::channel::<Vec<u8>>();
    let (tx_sha256, rx_sha256) = mpsc::channel::<Vec<u8>>();
    let reader = {
        let path = path.to_owned();
        let txs = vec![tx_md5, tx_sha1, tx_sha256];
        thread::spawn(move || -> io::Result<()> {
            let mut file = File::open(path)?;
            let mut buffer = [0u8; 8192];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                let chunk = buffer[..bytes_read].to_vec();
                for tx in &txs {
                    tx.send(chunk.clone()).unwrap();
                }
            }
            drop(txs);
            Ok(())
        })
    };

    fn spawn_hasher<H>(rx: mpsc::Receiver<Vec<u8>>) -> thread::JoinHandle<String>
    where
        H: DigestTrait + Send + 'static,
        <H as OutputSizeUser>::OutputSize: ArrayLength<u8> + Add,
        <<H as OutputSizeUser>::OutputSize as Add>::Output: ArrayLength<u8>,
    {
        thread::spawn(move || {
            let mut hasher = H::new();
            for chunk in rx {
                hasher.update(&chunk);
            }
            format!("{:x}", hasher.finalize())
        })
    }
    let hashers = vec![
        spawn_hasher::<Md5>(rx_md5),
        spawn_hasher::<Sha1>(rx_sha1),
        spawn_hasher::<Sha256>(rx_sha256),
    ];
    reader.join().unwrap()?;
    let (md5, sha1, sha256) = {
        let mut results = hashers
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        (results.remove(0), results.remove(0), results.remove(0))
    };
    Ok((md5, sha1, sha256))
}

fn check_hash(
    file: &Path,
    known_hashes: &HashSet<String>,
) -> io::Result<(bool, String, String, String)> {
    let (md5, sha1, sha256) = compute_hashes(file)?;
    let md5_lower = md5.to_ascii_lowercase();
    let sha1_lower = sha1.to_ascii_lowercase();
    let sha256_lower = sha256.to_ascii_lowercase();
    let matching_hash = known_hashes.contains(&md5_lower)
        || known_hashes.contains(&sha1_lower)
        || known_hashes.contains(&sha256_lower);
    Ok((matching_hash, md5, sha1, sha256))
}

fn check_rules(
    file_path: &Path,
    rules: &Rules,
) -> Result<(bool, Vec<String>), Box<dyn std::error::Error>> {
    let results = rules.scan_file(file_path, 5)?;
    let identifiers: Vec<String> = results
        .iter()
        .map(|pair| pair.identifier.to_string())
        .collect();
    if identifiers.is_empty() {
        Ok((false, vec![]))
    } else {
        Ok((true, identifiers))
    }
}

pub fn scan_file(file: &Path) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let known_hashes = load_hashes()?;
    let yara_rules = load_rules()?;
    let (hash_match, md5, sha1, sha256) = check_hash(file, &known_hashes)?;
    let (yara_match, yara_rules) = check_rules(file, &yara_rules)?;

    let result = ScanResult {
        hash_match,
        yara_match,
        yara_rules,
        md5,
        sha1,
        sha256,
    };
    Ok(result)
}
