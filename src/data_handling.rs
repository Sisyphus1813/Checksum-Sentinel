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

use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use serde::Deserialize;
use yara::{Compiler, Rules};

#[derive(Deserialize)]
struct Config {
    directories: Vec<String>,
}

pub fn load_directories() -> io::Result<Vec<String>> {
    let file = File::open("/etc/css/directories_monitor.json")?;
    let config: Config = serde_json::from_reader(file)?;
    Ok(config.directories)
}

pub fn load_hashes() -> io::Result<HashSet<String>> {
    let mut set = HashSet::new();
    let dir = Path::new("/var/lib/css/hashes/");
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Warning: could not read directory {}: {e}", dir.display());
            return Ok(set);
        }
    };
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.is_file() {
                if let Ok(file) = File::open(&path) {
                    let reader = BufReader::new(file);
                    for line in reader.lines() {
                        let line = line?;
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            set.insert(trimmed.to_ascii_lowercase());
                        }
                    }
                } else {
                    eprintln!("Warning: could not open {}", path.display());
                }
            }
        }
    }
    Ok(set)
}

pub fn load_rules() -> Result<Rules, Box<dyn Error>> {
    let dir = Path::new("/var/lib/css/yara_rules/");
    let rules: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("yar") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    if rules.is_empty() {
        return Err("No YARA rule files found in /var/lib/css/yara_rules/".into());
    }
    let compiler = rules
        .into_iter()
        .try_fold(Compiler::new()?, |c, p| c.add_rules_file(p))?;
    Ok(compiler.compile_rules()?)
}
