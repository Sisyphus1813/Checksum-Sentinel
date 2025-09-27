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

#![allow(unused_imports)]
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use md5::digest::consts::False;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Digest};
use yara::Rules;
use std::collections::HashSet;
use crate::data_handling::{load_hashes, load_rules};



fn compute_hash<P: AsRef<Path>>(path: P) -> io::Result<(String, String, String)> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 8192];
    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        md5_hasher.update(&buffer[..bytes_read]);
        sha1_hasher.update(&buffer[..bytes_read]);
        sha256_hasher.update(&buffer[..bytes_read]);
    }
    let md5_str = format!("{:x}", md5_hasher.finalize());
    let sha1_str = format!("{:x}", sha1_hasher.finalize());
    let sha256_str = format!("{:x}", sha256_hasher.finalize());

    Ok((md5_str, sha1_str, sha256_str))
}

fn check_hash(file: &Path, known_hashes: &HashSet<String>) -> io::Result<bool> {
    let (md5, sha1, sha256) = compute_hash(file)?;
    println!("MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}\n");
    let md5_lower = md5.to_ascii_lowercase();
    let sha1_lower = sha1.to_ascii_lowercase();
    let sha256_lower = sha256.to_ascii_lowercase();
    let matching_hash = known_hashes.contains(&md5_lower)
        || known_hashes.contains(&sha1_lower)
        || known_hashes.contains(&sha256_lower);
    Ok(matching_hash)
}


fn check_rules(file_path: &Path, rules: &Rules) -> Result<(bool, Vec<String>), Box<dyn std::error::Error>> {
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

pub fn scan_file(file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let known_hashes = crate::data_handling::load_hashes()?;
    let yara_rules = crate::data_handling::load_rules()?;
    let matching_hash = check_hash(file, &known_hashes)?;
    let matching_yara = check_rules(file, &yara_rules)?;
    let mut hits = 0;
    match matching_hash {
        true => {
            println!("****Matching malicious hash found!!****\n");
            hits += 1;
        }
        false => {
            println!("No matching malicious hash found.\n");
        }
    }
    match matching_yara {
        (true, identifiers) => {
            println!("****Matching YARA rule(s) found!!****");
            hits += 1;
            for id in identifiers {
                println!("- {}", id);
            }
            println!("\n");
        }
        (false, _) => {
            println!("No matching YARA rule found.\n");
        }
    }
    if hits == 0 {
        println!("VERDICT: No known malicious indicators detected.");
    } else if hits == 1 {
        println!("VERDICT: Indicators suggest the possible presence of malware.");
    } else if hits == 2 {
        println!("VERDICT: Multiple indicators suggest the probable presence of malware.");
    }
    println!("Note: Detections or the absence thereof do not guarantee compromise nor safety. Results reflect current rule and hash databases.");
    Ok(())
}
