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

use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;
use crate::checks::scan_file;


pub fn watch_directories(dirs: Vec<String>) -> notify::Result<()> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        tx.send(res).unwrap();
    })?;
    for dir in &dirs {
        watcher.watch(Path::new(dir), RecursiveMode::NonRecursive)?;
    }
    loop {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(event)) => handle_event(event),
            Ok(Err(e)) => eprintln!("Watch error: {:?}", e),
            Err(_) => {}
        }
    }
}

fn handle_event(event: Event) {
    if let EventKind::Create(_) = event.kind {
        for path in event.paths {
            if path.is_file() {
                if let Err(e) = scan_file(&path) {
                    eprintln!("Failed to check {:?}: {e}", path);
                }
            }
        }
    }
}
