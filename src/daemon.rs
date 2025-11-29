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

use crate::checks::scan_file;
use crate::data_handling::load_directories;
use crate::user_notification::notify_user;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

pub fn watch_directories() -> notify::Result<()> {
    let dirs: Vec<String> = load_directories()?;
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        tx.send(res).unwrap();
    })?;
    for dir in &dirs {
        watcher.watch(Path::new(dir), RecursiveMode::Recursive)?;
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
                match scan_file(&path) {
                    Ok(result) => notify_user(&path, &result, false),
                    Err(e) => eprintln!("Failed to check {:?}: {e}", path),
                }
            }
        }
    }
}
