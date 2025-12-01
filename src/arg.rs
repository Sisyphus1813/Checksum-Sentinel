use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "Checksum-Sentinel")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a file
    Scan {
        /// Path to file
        file: String,
    },
    /// Update Hashes and/or Yara rules
    Update {
        /// Update recent hashes
        #[arg(short, long)]
        recent: bool,

        /// Update persistent hashes
        #[arg(short, long)]
        persistent: bool,

        /// Update Yara rules
        #[arg(short, long)]
        yara: bool,
    },
    /// Watch directories specified in /etc/css/
    Watch,
}
