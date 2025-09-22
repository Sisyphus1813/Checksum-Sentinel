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

use notify::{RecommendedWatcher, RecursiveMode, Event, EventKind, Watcher};
use std::io::{self, BufRead, BufReader, Read};
use sha2::{Sha256, Digest};
use sha1::Sha1;
use md5::Md5;
use notify_rust::Notification;
use std::collections::HashSet;
use std::sync::mpsc::channel;
use std::path::{Path};
use std::time::Duration;
use std::fs::File;

#[derive(serde::Deserialize)]
struct Config {
    directories: Vec<String>,
}

fn load_directories() -> io::Result<Vec<String>> {
    let file = File::open("/etc/css/directories_monitor.json")?;
    let config: Config = serde_json::from_reader(file)?;
    Ok(config.directories)
}

fn watch_directories(dirs: Vec<String>, known_hashes: HashSet<String>) -> notify::Result<()> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        tx.send(res).unwrap();
    })?;
    for dir in &dirs {
        watcher.watch(Path::new(dir), RecursiveMode::NonRecursive)?;
    }
    loop {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(event)) => handle_event(event, &known_hashes),
            Ok(Err(e)) => eprintln!("Watch error: {:?}", e),
            Err(_) => {}
        }
    }
}

fn handle_event(event: Event, known_hashes: &HashSet<String>) {
    if let EventKind::Create(_) = event.kind {
        for path in event.paths {
            if path.is_file() {
                match compute_hashes(&path) {
                    Ok((md5, sha1, sha256)) => {
                        if known_hashes.contains(&md5)
                            || known_hashes.contains(&sha1)
                            || known_hashes.contains(&sha256)
                        {
                            if let Err(e) = Notification::new()
                                .summary("Hashwatch Alert")
                                .body(&format!("Possible malicious file detected: {:?}", path))
                                .icon("dialog-warning")
                                .show()
                            {
                                eprintln!("Failed to send detection notification: {e:?}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to compute hashes for {:?}: {e}", path);
                    }
                }
            }
        }
    }
}


fn load_hashes() -> io::Result<HashSet<String>> {
    let mut set = HashSet::new();
    let files = [
        "/var/lib/css/hashes.txt",
        "/var/lib/css/persistent_hashes.txt",
    ];
    for file_path in &files {
        if let Ok(file) = File::open(file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    set.insert(trimmed.to_ascii_lowercase());
                }
            }
        } else {
            eprintln!("Warning: could not open {}", file_path);
        }
    }
    Ok(set)
}

fn compute_hashes<P: AsRef<Path>>(path: P) -> io::Result<(String, String, String)> {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let known_hashes = load_hashes()?;
    if let Some(file_path) = std::env::args().nth(1) {
        let (md5, sha1, sha256) = compute_hashes(&file_path)?;
        println!("MD5: {md5}\n\nSHA1: {sha1}\n\nSHA256: {sha256}\n");
        let md5_lower = md5.to_ascii_lowercase();
        let sha1_lower = sha1.to_ascii_lowercase();
        let sha256_lower = sha256.to_ascii_lowercase();
        if known_hashes.contains(&md5_lower)
            || known_hashes.contains(&sha1_lower)
            || known_hashes.contains(&sha256_lower)
        {
            println!("Verdict: ****File hash matches that of a known malicious file!****");
        } else {
            println!("Verdict: File hash does not match the hash of stored malicious hashes.");
        }
        return Ok(());
    }
    let dirs = load_directories()?;
    watch_directories(dirs, known_hashes)?;
    Ok(())
}
