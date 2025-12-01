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

mod arg;
mod checks;
mod daemon;
mod data_handling;
mod poll_sources;
mod user_notification;

use crate::checks::scan_file;
use crate::daemon::watch_directories;
use crate::data_handling::setup;
use crate::user_notification::notify_user;
use arg::{Cli, Commands};
use clap::Parser;
use log::error;
use poll_sources::{poll_yara, update};
use std::path::Path;

fn main() {
    env_logger::init();
    if let Err(e) = setup() {
        error!("Failed to complete directory setup process: {e}");
    }
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { file } => {
            let path = Path::new(&file);
            match scan_file(path) {
                Ok(result) => notify_user(path, &result, true),
                Err(e) => eprintln!("Error scanning file: {e}"),
            }
        }
        Commands::Update {
            recent,
            persistent,
            yara,
        } => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let client = reqwest::Client::new();
                if yara {
                    if let Err(e) = poll_yara(&client).await {
                        error!("Error updating YARA rules: {e}");
                    }
                }
                if recent || persistent {
                    if let Err(e) = update(&client, persistent).await {
                        eprintln!("Error updating hashes: {e}");
                    }
                }
            })
        }
        Commands::Watch => {
            if let Err(e) = watch_directories() {
                error!("Encountered an error while attempting to watch directories: {e}");
            }
        }
    }
}
