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

use crate::checks::scan_file;
use crate::daemon::watch_directories;
use crate::data_handling::{load_directories};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(file_path) = std::env::args().nth(1) {
        scan_file(Path::new(&file_path))?;
    } else {
        let dirs: Vec<String> = load_directories()?;
        watch_directories(dirs)?;
    }
    Ok(())
}
