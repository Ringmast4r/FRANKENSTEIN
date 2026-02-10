<p align="center">
<img src="assets/week%20computer%20GIF.gif" width="500">
</p>

<h1 align="center">FRANKENSTEIN</h1>
<p align="center">
<img src="https://komarev.com/ghpvc/?username=Ringmast4r-FRANKENSTEIN&label=Visitors&color=00dc50&style=flat" alt="visitors">
</p>
<p align="center"><strong>Dual-Phenomenology Site Checker</strong></p>
<p align="center"><em>For _m0usem0use_ & ziggy</em></p>
<p align="center">
<a href="https://buymeacoffee.com/ringmast4r"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>
<p align="center">
<em>DNS + HTTP/S probing, 50 concurrent workers, TLS cert analysis, retry pass, response time percentiles</em>
</p>

---

## What It Does

Frankenstein checks if websites are alive using two independent phenomena:

**Phenomenon 1 — DNS Resolution**
- A/AAAA, CNAME, MX, and NS record lookups
- Identifies domains that resolve but have no web server

**Phenomenon 2 — HTTP/S Probe**
- Status codes, page titles, server software
- Full TLS certificate analysis (issuer, CN, expiry, self-signed detection)
- Redirect chain tracking
- Security header collection (HSTS, X-Frame-Options, Cache-Control)
- Response time measurement

A site is classified as:
- **ALIVE** — DNS resolves AND HTTP responds
- **DNS-ONLY** — DNS resolves but no HTTP response
- **DEAD** — Neither DNS nor HTTP responds

## Features

- **50 concurrent workers** — bulk scan thousands of domains fast
- **Retry pass** — failed domains get a second attempt with 3x timeout
- **Response time percentiles** — p50, p90, p95 stats after every scan
- **SQLite database** — all results persisted, rescannable, exportable
- **CSV export** — one-click export of all scan data
- **TLS certificate alerts** — self-signed certs, expiring certs flagged
- **DB Viewer** — browser-based HTML viewer with charts, filters, search, and sorting
- **Full TUI** — interactive terminal interface, no browser needed
- **Cross-platform** — Windows, Linux, and macOS

---

## Installation

### Option 1: Download Pre-Built Binary

Pre-built binaries are included in the repo:

| Platform | Binary |
|----------|--------|
| Windows | `WINDOWS/frankenstein.exe` |
| Linux / Kali | `LINUX/frankenstein` |
| macOS | `MACOS/frankenstein` |

> **macOS note:** If no pre-built binary is available in `MACOS/`, build from source with Option 2 below.

### Option 2: Build From Source

Requires [Go 1.23+](https://go.dev/dl/).

```bash
# Clone the repo
git clone https://github.com/Ringmast4r/FRANKENSTEIN.git
cd FRANKENSTEIN/src

# Build for your platform
go build -o frankenstein .
```

On macOS, the binary builds natively — no cross-compilation needed:

```bash
cd FRANKENSTEIN/src
go build -o frankenstein .
mv frankenstein ../
```

---

## Quick Start

### Linux / Kali

```bash
git clone https://github.com/Ringmast4r/FRANKENSTEIN.git
cd FRANKENSTEIN
chmod +x LINUX/frankenstein
./LINUX/frankenstein
```

### macOS

```bash
git clone https://github.com/Ringmast4r/FRANKENSTEIN.git
cd FRANKENSTEIN

# If pre-built binary exists:
chmod +x MACOS/frankenstein
./MACOS/frankenstein

# Or build from source:
cd src && go build -o ../MACOS/frankenstein . && cd ..
./MACOS/frankenstein
```

### Windows

```
git clone https://github.com/Ringmast4r/FRANKENSTEIN.git
cd FRANKENSTEIN
WINDOWS\frankenstein.exe
```

### CLI Flags

```
-db <path>       Custom database path (default: frankenstein.db)
-t <duration>    Custom timeout (default: 15s, e.g. -t 30s)
```

---

## Usage

### Single Domain Check

Select option `1` from the menu and type any domain:

```
Enter domain: example.com
```

Frankenstein runs both phenomena (DNS + HTTP) and gives a full breakdown — IPs, CNAME, MX, NS, HTTP status, title, server, TLS cert details, redirect chain, and security headers.

### Bulk Scan

**From the targets/ folder:**

Drop `.txt` files with one domain per line into the `targets/` folder, then select option `2` from the menu.

```
# Example: targets/my-sites.txt
example.com
github.com
google.com
```

**From any file path:**

Select option `3` and paste the full path to any `.txt` file on your system.

### Scan Flow

```
Load targets
  → Pass 1: 50 concurrent workers scan all domains
    → DNS resolution (A/AAAA, CNAME, MX, NS)
    → HTTP/S probe (status, title, headers, TLS cert)
  → Pass 2: Retry failed domains with 3x timeout
  → Summary: alive/dns-only/dead counts + response time percentiles (p50, p90, p95)
```

### View Results

| Key | Action |
|-----|--------|
| 1 | Check Single Domain |
| 2 | Bulk Scan from targets/ |
| 3 | Bulk Scan from File Path |
| 4 | View Alive Sites |
| 5 | View DNS-Only Sites |
| 6 | View Dead Sites |
| 7 | Export Results to CSV |
| 8 | DB Statistics |
| 9 | Rescan All (Refresh) |
| 0 | Exit |

### Keyboard Controls

| Key | Action |
|-----|--------|
| Arrow keys | Navigate menu / scroll results |
| Enter | Select menu item / confirm input |
| Esc | Cancel scan / go back / quit |
| PgUp / PgDn | Scroll output during scan |
| Q | Quit |
| 1-9, 0 | Jump directly to menu option |

---

## Running Through Tor / Proxychains

If you're running on Kali with an OPSEC stack, prefix with `proxychains4` to route all traffic through Tor:

```bash
cd FRANKENSTEIN
proxychains4 ./LINUX/frankenstein
```

All DNS lookups and HTTP requests will go through your SOCKS5 proxy. Works the same on macOS if you have Tor and proxychains installed:

```bash
proxychains4 ./frankenstein
```

---

## DB Viewer

Open `frankenstein-db-viewer.html` in any browser and drag your `frankenstein.db` file onto it. No server needed — runs entirely in the browser.

**Features:**
- Dashboard with status breakdown bar chart
- Sortable, searchable, filterable table of all sites
- Click any row for full detail modal (DNS + HTTP + TLS)
- Response time distribution chart
- Server software breakdown
- TLS issuer breakdown
- CSV export

---

## Database

All scan results are stored in `frankenstein.db` (SQLite). The database is auto-created on first run.

**DB path resolution order:**
1. If the binary is inside `LINUX/` or `WINDOWS/`, the DB goes in the parent (project root)
2. If `~/Documents/recon-suite/Frankenstein/` exists, the DB goes there
3. Otherwise, the DB goes in the current working directory
4. `-db` flag overrides everything

The database persists across runs. Use option `9` (Rescan All) to refresh all existing entries.

---

## Building From Source

### Prerequisites

- [Go 1.23+](https://go.dev/dl/)

### Build

```bash
cd FRANKENSTEIN/src

# Linux / macOS
go build -o frankenstein .

# Windows
go build -o frankenstein.exe .
```

### Dependencies

All dependencies are vendored through Go modules — `go build` handles everything automatically:

- [tcell](https://github.com/gdamore/tcell) — terminal UI framework
- [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) — pure-Go SQLite driver (no CGO, no system dependencies)
- [go-runewidth](https://github.com/mattn/go-runewidth) — Unicode character width handling

No CGO. No system libraries. Single static binary on every platform.

---

## Project Structure

```
FRANKENSTEIN/
├── src/
│   ├── main.go              # All source code (single-file architecture)
│   ├── console_windows.go   # Windows console UTF-8 + ANSI setup
│   ├── go.mod               # Go module definition
│   └── go.sum               # Dependency checksums
├── WINDOWS/
│   └── frankenstein.exe     # Windows binary
├── LINUX/
│   └── frankenstein         # Linux binary
├── MACOS/
│   └── frankenstein         # macOS binary (build from source)
├── assets/                  # Media
├── targets/                 # Drop .txt target files here
├── frankenstein-db-viewer.html  # Browser-based DB explorer
└── README.md
```

---

<p align="center"><em>This one's for <strong>_m0usem0use_</strong> and <strong>ziggy</strong></em></p>

<p align="center">
<a href="https://buymeacoffee.com/ringmast4r"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>
