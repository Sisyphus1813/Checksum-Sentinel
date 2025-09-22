# Checksum Sentinel (CSS)

Checksum Sentinel (CSS) is a hybrid Rust/Python project designed to automatically fetch, store, and monitor known malicious file hashes (MD5, SHA1, SHA256) from open source threat intelligence feeds. It integrates with `systemd` services and timers to continuously update hash sets and provide a daemonized monitoring process that checks directories for compromised files.

This project is intended to serve as a **secure background service**: it silently updates threat feeds, stores verified hashes locally, and enables continuous monitoring of system directories for potential malware or unwanted files. In addition, the `css` binary can also be run in single-shot mode against a specific file, allowing you to check its hash directly without running the daemon.

---

## Features

- **Threat Feed Integration**\
  Pulls from multiple reputable malicious hash feeds:

  - [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) (persistent + recent)
  - [Community-maintained GitHub malicious hash lists](https://github.com/romainmarcoux/malicious-hash/) (recent only).

- **Python Feed Poller** (`css_update/__init__.py`)

  - Fetches and merges hashes from multiple sources asynchronously via `aiohttp` + `asyncio`.
  - Handles both plain text and ZIP-compressed hash exports.
  - Maintains two hash sets:
    - **Persistent Hashes** (`/var/lib/css/persistent_hashes.txt`) → long-lived database of known bad hashes.
    - **Recent Hashes** (`/var/lib/css/hashes.txt`) → short-term / fast-updating database.
  - CLI options:
    - `--update-persistent` → refresh both persistent and recent sets.
    - `--update-recent` → refresh only the recent set.

- **Rust Monitoring Daemon** (`main.rs` → `css` binary)

  - Loads hash lists into memory (`HashSet`) for fast O(1) lookups.
  - Scans monitored directories for file hashes.
    - Note that at this time the daemon ONLY scans top level files in the given directory.
  - Detects and reports any match against known malicious hashes.
  - Designed for **continuous background execution** under `systemd`.

- **Systemd Integration**

  - **Services**:
    - `css.service` → Daemon for live directory monitoring.
    - `css-update-recent.service` → Handles running css-update with "recent" flag
    - `css-update-persistent.service` → Handles running css-update with "persistent" flag
  - **Timers**:
    - `css-update-recent.timer` → Refreshes recent feeds periodically.
    - `css-update-persistent.timer` → Refreshes persistent feeds less frequently.
  - Option for **no-daemon mode** (only updates without running a continuous daemon).


- **Install Script** (`install.sh`)

  - **Dependency Management:** Installs the Python component via `pip3` (defined in `pyproject.toml`) and compiles the Rust component via `cargo build --release`. This ensures both runtime environments (Python for feed updates, Rust for the file watcher) are properly set up.

  - **Binary Deployment:** Moves the compiled Rust binary (`css`) into `/usr/local/bin/` so it is globally available in the system PATH for execution by `systemd` or users.

  - **Systemd Integration:** Installs all relevant `.service` and `.timer` units into `/etc/systemd/system/`. This integrates the updater and watcher into the host’s init system, allowing automatic scheduling (via timers) and persistent background execution (via services).

  - **SELinux Context Correction:** Calls `restorecon` on installed unit files to assign the correct SELinux labels (`systemd_unit_file_t`). Without this step, SELinux sometimes blocks systemd from reading the new service definitions.

  - **Daemon and Timer Enablement:** Runs `systemctl daemon-reload` followed by `systemctl enable --now` for the timers (and optionally the watcher daemon). This makes the updater jobs active immediately and persistent across reboots.

---

## Installation

### Requirements

- Any systemd enabled Linux distribution
- Python 3.11+ (`aiohttp`, `asyncio`)
- Rust

### Steps

```bash
# Clone the repository
git clone https://github.com/Sisyphus1813/checksum-sentinel.git
cd checksum-sentinel

# Run installer
chmod +x install.sh
./install.sh
```

The installer will:

- Build the Rust binary (`cargo build --release`).
- Install it as `/usr/local/bin/css`.
- Run `pip install .` to fetch Python requirements from `pyproject.toml`.
- Move service/timer files into `/etc/systemd/system/`.
- Enable services and timers.

---

## Usage

### Update Hash Feeds

Manual update:

```bash
css_update.py --update-recent
css_update.py --update-persistent
```

Or use `systemd` timers (preferred):

```bash
sudo systemctl enable --now css-update-recent.timer
sudo systemctl enable --now css-update-persistent.timer
```

### Run Monitoring Daemon

Enable continuous monitoring:

```bash
sudo systemctl enable --now css.service
```

Stop monitoring:

```bash
sudo systemctl stop css.service
```

To use as a single shot binary:

```bash
css /path/to/file_to_scan
```


### Directory Configuration

If running as a systemd daemon, the binary reads directories to monitor from `/etc/css/directories_monitor.json`.\
Default: an empty json file only containing the "directories" key.
An example file:

```json
{
  "directories": [
    "/home/user/Downloads",
    "/var/log",
    "/tmp/test"
  ]
}
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with detailed description.

Bug reports and feature requests are encouraged via GitHub Issues.

---

## Security Notes

- Checksum-Sentinel does **not** differentiate between Windows/Linux malware → it currently only notifies you when a known malicious hash is found, regardless of target platform. At present it does not block or contain files. Work is in progress to integrate Checksum-Sentinel with SELinux and AppArmor to automatically contain files flagged with bad hashes.
- Persistent and recent feeds can grow large (persistent database often contains > 3,000,000+ hashes), but `HashSet`-based lookups remain efficient.
- All services must run as **root** to monitor system-wide directories and write to /etc/ and /var/ directories.

---

## License

This project is licensed under the GNU General Public License (GPL v3).\
See the `LICENSE` file for full details.

---

## Project Structure

```
├── css_update/
│   ├── __init__.py                   # Main Python updater logic: fetches malicious hash feeds,
│   │                                 # saves persistent/recent hash sets to /var/lib/css/
│   └── __main__.py                   # Optional entrypoint, allows running `python -m css_update`
│
├── src/
│   └── main.rs                       # Rust daemon: watches configured directories, computes
│                                     # file hashes (MD5/SHA1/SHA256), compares them to known
│                                     # bad hashes, and sends desktop notifications if matched
│
├── systemd/
│   ├── no-daemon/                    # Alternative unit files if you don’t want to run the watcher daemon
│   │   ├── css-update-persistent.service  # Service triggered by persistent.timer — updates full hash set
│   │   └── css-update-recent.service      # Service triggered by recent.timer — updates only recent feeds
│   │
│   ├── css-update-persistent.service # Service triggered by persistent.timer — updates full hash set
│   ├── css-update-persistent.timer   # Timer: runs daily to refresh persistent hash feeds
│   ├── css-update-recent.service     # Service triggered by recent.timer — updates only recent feeds
│   ├── css-update-recent.timer       # Timer: runs every 3 hours to refresh recent hash feeds
│   └── css.service                   # Long-running systemd service for the `css` watcher binary
│
├── Cargo.lock                        # Rust lockfile: pins exact dependency versions
├── Cargo.toml                        # Rust project manifest and dependencies
├── install.sh                        # Installer script: builds binary, installs Python package,
│                                     # moves systemd units, enables timers, fixes SELinux labels
├── pyproject.toml                    # Python project metadata, dependencies, and entrypoints
├── README.md                         # Project documentation (this file)
└── uv.lock                           # Python dependency lock (generated by `uv`/pdm/other resolver)
```
```
