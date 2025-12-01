# Checksum Sentinel (CSS)

Checksum Sentinel (CSS) is a Rust project designed to automatically fetch, store, and monitor known malicious file hashes and YARA rules from open source threat intelligence feeds. It integrates with `systemd` services and timers to continuously update hash sets and provide a daemonized monitoring process that checks directories for compromised files.

This project is intended to serve as a **secure background service**: it silently updates threat feeds, stores verified hashes locally, and enables continuous monitoring of system directories for potential malware or unwanted files. In addition, the `checksum-sentinel` binary can also be run in single-shot mode against a specific file, allowing you to check its hash directly without running the daemon. At this time, we provide a binding to update YARA rules, but it must be called manually.

---

## Features

- **Threat Feed Integration**\
  Pulls from multiple reputable malicious hash feeds:
  - [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) (persistent + recent)
  - [Community-maintained GitHub malicious hash lists](https://github.com/romainmarcoux/malicious-hash/) (recent only).
  - [yara-forge](https://github.com/YARAHQ/yara-forge) (currently the only YARA rules source)

- **Rust Feed Poller** (`poll_sources.rs`)
  - Fetches and merges hashes from multiple sources asynchronously via `reqwest` + `tokio`.
  - Handles both plain text and ZIP-compressed hash exports.
  - Hash files are stored in `/var/lib/css/hashes/` directory, where all files are loaded and merged at runtime.

- **Rust Monitoring Daemon** (`checksum-sentinel` binary)
  - Loads all hash files from `/var/lib/css/hashes/` into memory (`HashSet`) for fast O(1) lookups.
  - Computes MD5, SHA1, and SHA256 hashes in parallel using multi-threaded processing for efficient file scanning.
  - Watches monitored directories **recursively** for new file creation events.
  - Scans new files against known malicious hashes and YARA rules (loaded from `/var/lib/css/yara_rules/`).
  - Detects and reports any match against known malicious hashes or YARA rule matches.
  - **Desktop notifications** using `notify-rust` (Critical for detections, Normal for clean scans).
  - Falls back to logging if desktop notifications fail.
  - Designed for **continuous background execution** under `systemd`.

- **Systemd Integration**
  - **Services**:
    - `css.service` → Daemon for live directory monitoring.
    - `css-update-recent.service` → Handles running checksum-sentinel update with "recent" flag
    - `css-update-persistent.service` → Handles running checksum-sentinel update with "persistent" flag
  - **Timers**:
    - `css-update-recent.timer` → Refreshes recent feeds periodically.
    - `css-update-persistent.timer` → Refreshes persistent feeds less frequently.
  - Option for **no-daemon mode** (only updates without running a continuous daemon).

## Installation

### Requirements

- Any systemd enabled Linux distribution
- Rust
- D-Bus (for desktop notifications)

### Steps

```bash
# Clone the repository
git clone https://github.com/Sisyphus1813/checksum-sentinel.git
cd checksum-sentinel

# Run installer
sudo chmod +x install.sh
./install.sh
```

Installation script will:

- Ask wether you intend to run the application as a monitoring service or only a oneshot scanner.
- Build the Rust binary.
- Deploy the appropriate systemd services and timers.
- Resolve SELinux context issues.
- Enable them for automatic updates and (if applicable) background scanning.

---

## Usage

### Update Hash Feeds

Manual update:

```bash
sudo checksum-sentinel update --recent
sudo checksum-sentinel update --persistent
sudo checksum-sentinel update --yara
```

Flags can be combined:

```bash
sudo checksum-sentinel update --recent --persistent --yara
sudo checksum-sentinel update -r -p -y
```

Or use `systemd` timers:

```bash
sudo systemctl enable --now css-update-recent.timer
sudo systemctl enable --now css-update-persistent.timer
```

Note that the system timers currently only update stored hashes. Yara rules must be updated manually from time to time (I reccomend once a month). Yara rule updates are not currently set up as a system service because the only polled source currently only updates sporatically. This will be mitigated or fixed in a future update.

### Monitoring Daemon

Enable continuous monitoring:

```bash
sudo systemctl enable --now css.service
```

Stop monitoring:

```bash
sudo systemctl disable --now css.service
```

To use as a single shot binary:

```bash
checksum-sentinel scan /path/to/file_to_scan
```

### Directory Configuration

If running as a systemd daemon, the binary reads directories to monitor from `/etc/css/directories_monitor.json`.\
Default: monitors the current user's Downloads directory (`/home/<user>/Downloads/`).

An example file:

```json
{
  "directories": ["/home/user/Downloads", "/var/log", "/tmp/test"]
}
```

Directories are monitored **recursively**, meaning all subdirectories will also be watched for new file creation events.

---

## Data Storage

- **Hash files**: `/var/lib/css/hashes/` — All files in this directory are loaded and merged. Each file should contain one hash per line (MD5, SHA1, or SHA256).
- **YARA rules**: `/var/lib/css/yara_rules/` — All `.yar` files in this directory are compiled and used for scanning.
- **Configuration**: `/etc/css/directories_monitor.json` — JSON file specifying directories to monitor.

---

## Scan Output

When scanning files CSS reports:

- **File information**: Name, path, and computed hashes (MD5, SHA1, SHA256)
- **Hash match status**: Whether any computed hash matches a known malicious hash
- **YARA match status**: Whether any YARA rules matched, including the rule identifiers
- **Verdict**: Summary indicating whether malicious indicators were detected

In daemon mode, results are displayed as desktop notifications. In single-shot mode, results are printed to the console.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with detailed description.

Bug reports and feature requests are encouraged via GitHub Issues.

---

## Help wanted!!

At this stage, the project does not yet include a comprehensive or verified **testing corpus** for validation of detection accuracy. This means that while the scanning logic and rule integration have been implemented, broader real-world testing across diverse samples remains limited.

If you maintain or have access to a **reliable, well-curated testing corpus** of files suitable for open research or tool evaluation, your contribution would be invaluable. We welcome **pull requests** that:

- Introduce or reference safe, shareable sample sets
- Add reproducible test cases or corpus integration scripts
- Improve coverage or validation of rule-based and hash-based detections

Please ensure any submitted corpus data complies with applicable laws and does not contain live, active malware. The goal is to expand testing responsibly while improving the tool's accuracy and robustness for all users.

---

## Project Structure

```
├── src/
│   ├── arg.rs                      # CLI argument parsing using clap
│   ├── checks.rs                   # Performs the core functionality by computing hashes, and checking the file for either a matching malicious hash or YARA rule.
│   ├── daemon.rs                   # Handles the filesystem watcher component
│   ├── data_handling.rs            # Manages configuration, loading monitored directories, known file hashes, and compiling YARA rules from stored sources
│   ├── main.rs                     # Serves as the program entry point
│   ├── poll_sources.rs             # Fetches malicious hash feeds and YARA rules from remote sources
│   └── user_notification.rs        # Handles sending desktop notifications and returning results to console
│
├── systemd/
│   ├── no-daemon/                         # Alternative unit files if you don't want to run the watcher daemon
│   │   ├── css-update-persistent.service  # Service triggered by persistent.timer — updates full hash set
│   │   └── css-update-recent.service      # Service triggered by recent.timer — updates only recent feeds
│   │
│   ├── css-update-persistent.service # Service triggered by persistent.timer — updates full hash set
│   ├── css-update-persistent.timer   # Timer: runs daily to refresh persistent hash feeds
│   ├── css-update-recent.service     # Service triggered by recent.timer — updates only recent feeds
│   ├── css-update-recent.timer       # Timer: runs every 3 hours to refresh recent hash feeds
│   └── css.service                   # Long-running systemd service for the `checksum-sentinel` watcher binary
│
├── Cargo.lock                        # Rust lockfile: pins exact dependency versions
├── Cargo.toml                        # Rust project manifest and dependencies
├── install.sh                        # Installer script: builds binary, moves systemd units, enables timers, fixes SELinux labels
└── README.md                         # Project documentation (this file)

```

---

## Security Notes

- Checksum-Sentinel does **not** differentiate between Windows/Linux malware; it currently only notifies you when a known malicious hash or file with a matching YARA rule is found, regardless of target platform. At present it does not move files to containment. Work is in progress to integrate Checksum-Sentinel with SELinux and AppArmor to automatically move files to containment if they are flagged with bad hashes or matching YARA rules.
- All services must run as **root** to monitor system-wide directories and write to /etc/ and /var/ directories.
- Desktop notifications require a running D-Bus session; if unavailable, results are logged instead.

---

## License

This project is licensed under the GNU General Public License (GPL v3).\
See the [LICENSE](LICENSE) file for full details.
