<p align="center">
<img src="assets/week%20computer%20GIF.gif" width="500">
</p>

<h1 align="center">FRANKENSTEIN</h1>
<p align="center">
<img src="https://komarev.com/ghpvc/?username=Ringmast4r-FRANKENSTEIN&label=Visitors&color=00dc50&style=flat" alt="visitors">
</p>
<p align="center"><strong>Dual-Phenomenology Site Checker</strong></p>
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
- **DB Viewer** — browser-based HTML viewer with charts, filters, search, and sorting (open `db-viewer.html`)
- **Full TUI** — interactive terminal interface, no browser needed
- **Cross-platform** — Windows and Linux binaries included

## Quick Start

### Windows
```
cd Frankenstein
frankenstein.exe
```

### Linux
```
cd Frankenstein
chmod +x LINUX/frankenstein
./LINUX/frankenstein
```

### CLI Flags
```
-db <path>       Custom database path (default: frankenstein.db)
-t <duration>    Custom timeout (default: 15s, e.g. -t 30s)
```

## Usage

Drop `.txt` files with one domain per line into the `targets/` folder, then select **Bulk Scan from targets/** from the menu.

Or use **Check Single Domain** for one-off lookups.

```
# Example target file (targets/my-sites.txt)
example.com
github.com
google.com
```

## Menu Options

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

## DB Viewer

Open `db-viewer.html` in any browser and drag your `frankenstein.db` file onto it. Gives you:

- Dashboard with status breakdown and bar charts
- Sortable, searchable, filterable table of all sites
- Click any row for full detail modal (DNS + HTTP + TLS)
- Response time distribution chart
- Server software breakdown
- TLS issuer breakdown
- CSV export

## Project Structure

```
Frankenstein/
├── main.go                  # All source code (single-file architecture)
├── console_windows.go       # Windows console UTF-8 + ANSI setup
├── go.mod / go.sum           # Go module dependencies
├── frankenstein.db           # SQLite database (auto-created)
├── db-viewer.html            # Browser-based DB explorer
├── assets/                   # GIFs and media
├── targets/                  # Drop .txt target files here
├── logs/                     # Scan logs (auto-created)
├── LINUX/
│   ├── frankenstein          # Linux binary
│   └── db-viewer.html
└── WINDOWS/
    ├── frankenstein.exe      # Windows binary
    └── db-viewer.html
```

## Built With

- [Go](https://go.dev/) — single binary, no dependencies at runtime
- [tcell](https://github.com/gdamore/tcell) — terminal UI
- [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) — pure-Go SQLite (no CGO)
- [sql.js](https://github.com/sql-js/sql.js) — browser-side SQLite for DB Viewer
