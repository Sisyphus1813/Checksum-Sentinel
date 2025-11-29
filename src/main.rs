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

mod checks;
mod daemon;
mod data_handling;
mod user_notification;

use crate::checks::scan_file;
use crate::daemon::watch_directories;
use crate::user_notification::notify_user;
use log::error;
use std::path::Path;

fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        1 => {
            if let Err(e) = watch_directories() {
                error!("Error watching directories: {e}");
            }
        }
        2 => {
            let path = Path::new(&args[1]);
            match scan_file(path) {
                Ok(result) => notify_user(path, &result, true),
                Err(e) => eprintln!("Error scanning file: {e}"),
            }
        }
        _ => eprintln!("CSS currently only accepts a single file as an argument."),
    }
}
