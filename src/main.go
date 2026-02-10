package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/mattn/go-runewidth"
	_ "modernc.org/sqlite"
)

// ════════════════════════════════════════════════════════════════
// CONSTANTS & THEME
// ════════════════════════════════════════════════════════════════

const version = "2.0.0"
const appName = "Frankenstein"

const maxWorkers = 50 // concurrent goroutines for bulk scanning

var (
	ColorBackground = tcell.ColorBlack
	ColorText       = tcell.ColorWhite
	ColorPrimary    = tcell.NewRGBColor(0, 220, 80)    // Electric green
	ColorSuccess    = tcell.NewRGBColor(100, 255, 140)  // Light green
	ColorWarning    = tcell.NewRGBColor(255, 220, 0)    // Yellow
	ColorDanger     = tcell.NewRGBColor(255, 60, 60)    // Red
	ColorInfo       = tcell.NewRGBColor(80, 200, 255)   // Cyan
	ColorBorder     = tcell.NewRGBColor(0, 160, 60)     // Dark green
	ColorLogo       = tcell.NewRGBColor(0, 255, 100)    // Bright green
	ColorDim        = tcell.NewRGBColor(60, 140, 80)    // Dim green
	ColorBolt       = tcell.NewRGBColor(200, 255, 0)    // Yellow-green bolt
)

// ════════════════════════════════════════════════════════════════
// DATABASE
// ════════════════════════════════════════════════════════════════

type DB struct {
	conn *sql.DB
	path string
	mu   sync.Mutex
}

func NewDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db := &DB{conn: conn, path: path}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) Close() { db.conn.Close() }

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS sites (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT UNIQUE NOT NULL,
			first_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_checked DATETIME,
			times_checked INTEGER DEFAULT 0,
			dns_alive INTEGER DEFAULT 0,
			dns_ips TEXT DEFAULT '',
			dns_cnames TEXT DEFAULT '',
			dns_mx TEXT DEFAULT '',
			dns_ns TEXT DEFAULT '',
			dns_error TEXT DEFAULT '',
			http_alive INTEGER DEFAULT 0,
			http_status INTEGER DEFAULT 0,
			http_title TEXT DEFAULT '',
			http_server TEXT DEFAULT '',
			http_redirect TEXT DEFAULT '',
			http_tls INTEGER DEFAULT 0,
			http_tls_issuer TEXT DEFAULT '',
			http_error TEXT DEFAULT '',
			http_response_ms INTEGER DEFAULT 0,
			http_content_type TEXT DEFAULT '',
			http_powered_by TEXT DEFAULT '',
			http_via TEXT DEFAULT '',
			http_cache_control TEXT DEFAULT '',
			http_x_frame TEXT DEFAULT '',
			http_hsts TEXT DEFAULT '',
			http_tls_cn TEXT DEFAULT '',
			http_tls_expiry TEXT DEFAULT '',
			http_tls_days_left INTEGER DEFAULT 0,
			http_tls_self_signed INTEGER DEFAULT 0,
			http_redirect_chain TEXT DEFAULT '',
			status TEXT DEFAULT 'unknown'
		)
	`)
	if err != nil {
		return err
	}

	// v2 schema additions for existing databases
	alters := []string{
		"ALTER TABLE sites ADD COLUMN http_content_type TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_powered_by TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_via TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_cache_control TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_x_frame TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_hsts TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_tls_cn TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_tls_expiry TEXT DEFAULT ''",
		"ALTER TABLE sites ADD COLUMN http_tls_days_left INTEGER DEFAULT 0",
		"ALTER TABLE sites ADD COLUMN http_tls_self_signed INTEGER DEFAULT 0",
		"ALTER TABLE sites ADD COLUMN http_redirect_chain TEXT DEFAULT ''",
	}
	for _, q := range alters {
		db.conn.Exec(q) // ignore "duplicate column" errors for existing v2 DBs
	}

	return nil
}

type SiteRecord struct {
	Domain       string
	DNSAlive     bool
	DNSIPs       string
	DNSCnames    string
	DNSMX        string
	DNSNS        string
	DNSError     string
	HTTPAlive    bool
	HTTPStatus   int
	HTTPTitle    string
	HTTPServer   string
	HTTPRedirect string
	HTTPTLS      bool
	HTTPTLSIssuer string
	HTTPError    string
	HTTPRespMs   int64
	// v2 fields
	HTTPContentType   string
	HTTPPoweredBy     string
	HTTPVia           string
	HTTPCacheControl  string
	HTTPXFrame        string
	HTTPHSTS          string
	HTTPTLSCN         string
	HTTPTLSExpiry     string
	HTTPTLSDaysLeft   int
	HTTPTLSSelfSigned bool
	HTTPRedirectChain string
	Status            string
}

func (db *DB) UpsertSite(r SiteRecord) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec(`
		INSERT INTO sites (domain, last_checked, times_checked,
			dns_alive, dns_ips, dns_cnames, dns_mx, dns_ns, dns_error,
			http_alive, http_status, http_title, http_server, http_redirect,
			http_tls, http_tls_issuer, http_error, http_response_ms,
			http_content_type, http_powered_by, http_via, http_cache_control,
			http_x_frame, http_hsts, http_tls_cn, http_tls_expiry,
			http_tls_days_left, http_tls_self_signed, http_redirect_chain, status)
		VALUES (?, CURRENT_TIMESTAMP, 1,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			last_checked = CURRENT_TIMESTAMP,
			times_checked = times_checked + 1,
			dns_alive = excluded.dns_alive,
			dns_ips = excluded.dns_ips,
			dns_cnames = excluded.dns_cnames,
			dns_mx = excluded.dns_mx,
			dns_ns = excluded.dns_ns,
			dns_error = excluded.dns_error,
			http_alive = excluded.http_alive,
			http_status = excluded.http_status,
			http_title = excluded.http_title,
			http_server = excluded.http_server,
			http_redirect = excluded.http_redirect,
			http_tls = excluded.http_tls,
			http_tls_issuer = excluded.http_tls_issuer,
			http_error = excluded.http_error,
			http_response_ms = excluded.http_response_ms,
			http_content_type = excluded.http_content_type,
			http_powered_by = excluded.http_powered_by,
			http_via = excluded.http_via,
			http_cache_control = excluded.http_cache_control,
			http_x_frame = excluded.http_x_frame,
			http_hsts = excluded.http_hsts,
			http_tls_cn = excluded.http_tls_cn,
			http_tls_expiry = excluded.http_tls_expiry,
			http_tls_days_left = excluded.http_tls_days_left,
			http_tls_self_signed = excluded.http_tls_self_signed,
			http_redirect_chain = excluded.http_redirect_chain,
			status = excluded.status
	`, r.Domain,
		boolToInt(r.DNSAlive), r.DNSIPs, r.DNSCnames, r.DNSMX, r.DNSNS, r.DNSError,
		boolToInt(r.HTTPAlive), r.HTTPStatus, r.HTTPTitle, r.HTTPServer, r.HTTPRedirect,
		boolToInt(r.HTTPTLS), r.HTTPTLSIssuer, r.HTTPError, r.HTTPRespMs,
		r.HTTPContentType, r.HTTPPoweredBy, r.HTTPVia, r.HTTPCacheControl,
		r.HTTPXFrame, r.HTTPHSTS, r.HTTPTLSCN, r.HTTPTLSExpiry,
		r.HTTPTLSDaysLeft, boolToInt(r.HTTPTLSSelfSigned), r.HTTPRedirectChain, r.Status)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type DBStats struct {
	Total     int
	Alive     int
	DNSOnly   int
	Dead      int
	Errors    int
	HTTPSites int
}

func (db *DB) GetStats() DBStats {
	var s DBStats
	db.conn.QueryRow("SELECT COUNT(*) FROM sites").Scan(&s.Total)
	db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE status='alive'").Scan(&s.Alive)
	db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE status='dns_only'").Scan(&s.DNSOnly)
	db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE status='dead'").Scan(&s.Dead)
	db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE status='error'").Scan(&s.Errors)
	db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE http_tls=1").Scan(&s.HTTPSites)
	return s
}

func (db *DB) GetSitesByStatus(status string) []SiteRecord {
	rows, err := db.conn.Query(`
		SELECT domain, dns_alive, dns_ips, dns_cnames, dns_mx, dns_ns, dns_error,
			http_alive, http_status, http_title, http_server, http_redirect,
			http_tls, http_tls_issuer, http_error, http_response_ms,
			http_content_type, http_powered_by, http_via, http_cache_control,
			http_x_frame, http_hsts, http_tls_cn, http_tls_expiry,
			http_tls_days_left, http_tls_self_signed, http_redirect_chain, status
		FROM sites WHERE status=? ORDER BY domain`, status)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var sites []SiteRecord
	for rows.Next() {
		var r SiteRecord
		var dnsA, httpA, httpTLS, selfSigned int
		rows.Scan(&r.Domain, &dnsA, &r.DNSIPs, &r.DNSCnames, &r.DNSMX, &r.DNSNS, &r.DNSError,
			&httpA, &r.HTTPStatus, &r.HTTPTitle, &r.HTTPServer, &r.HTTPRedirect,
			&httpTLS, &r.HTTPTLSIssuer, &r.HTTPError, &r.HTTPRespMs,
			&r.HTTPContentType, &r.HTTPPoweredBy, &r.HTTPVia, &r.HTTPCacheControl,
			&r.HTTPXFrame, &r.HTTPHSTS, &r.HTTPTLSCN, &r.HTTPTLSExpiry,
			&r.HTTPTLSDaysLeft, &selfSigned, &r.HTTPRedirectChain, &r.Status)
		r.DNSAlive = dnsA == 1
		r.HTTPAlive = httpA == 1
		r.HTTPTLS = httpTLS == 1
		r.HTTPTLSSelfSigned = selfSigned == 1
		sites = append(sites, r)
	}
	return sites
}

func (db *DB) ExportCSV(path string) error {
	rows, err := db.conn.Query(`
		SELECT domain, status, dns_alive, dns_ips, http_alive, http_status,
			http_title, http_server, http_tls, http_response_ms,
			http_content_type, http_powered_by, http_tls_cn, http_tls_expiry,
			http_tls_days_left, http_tls_self_signed, http_redirect_chain,
			http_x_frame, http_hsts, last_checked
		FROM sites ORDER BY status, domain`)
	if err != nil {
		return err
	}
	defer rows.Close()

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "domain,status,dns_alive,dns_ips,http_alive,http_status,http_title,http_server,https,response_ms,content_type,x_powered_by,tls_cn,tls_expiry,tls_days_left,tls_self_signed,redirect_chain,x_frame_options,hsts,last_checked")
	for rows.Next() {
		var domain, status, ips, title, server string
		var contentType, poweredBy, tlsCN, tlsExpiry, redirectChain, xFrame, hsts, lastChecked string
		var dnsA, httpA, httpStatus, tls, tlsDaysLeft, selfSigned int
		var respMs int64
		rows.Scan(&domain, &status, &dnsA, &ips, &httpA, &httpStatus,
			&title, &server, &tls, &respMs,
			&contentType, &poweredBy, &tlsCN, &tlsExpiry,
			&tlsDaysLeft, &selfSigned, &redirectChain,
			&xFrame, &hsts, &lastChecked)
		title = strings.ReplaceAll(title, ",", ";")
		title = strings.ReplaceAll(title, "\"", "'")
		redirectChain = strings.ReplaceAll(redirectChain, ",", ";")
		fmt.Fprintf(f, "%s,%s,%d,%s,%d,%d,\"%s\",%s,%d,%d,%s,%s,%s,%s,%d,%d,\"%s\",%s,%s,%s\n",
			domain, status, dnsA, ips, httpA, httpStatus, title, server, tls, respMs,
			contentType, poweredBy, tlsCN, tlsExpiry, tlsDaysLeft, selfSigned,
			redirectChain, xFrame, hsts, lastChecked)
	}
	return nil
}

// ════════════════════════════════════════════════════════════════
// SITE CHECKER (DUAL PHENOMENOLOGY)
// ════════════════════════════════════════════════════════════════

type Checker struct {
	httpClient *http.Client
	resolver   *net.Resolver
	timeout    time.Duration
}

func NewChecker(timeout time.Duration) *Checker {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}
	return &Checker{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", "8.8.8.8:53")
			},
		},
		timeout: timeout,
	}
}

func (c *Checker) Check(ctx context.Context, domain string) SiteRecord {
	domain = cleanDomain(domain)
	r := SiteRecord{Domain: domain, Status: "unknown"}

	// PHENOMENON 1: DNS Resolution
	c.checkDNS(ctx, domain, &r)

	// PHENOMENON 2: HTTP Probe
	c.checkHTTP(ctx, domain, &r)

	// Determine status from dual phenomena
	if r.HTTPAlive {
		r.Status = "alive"
	} else if r.DNSAlive {
		r.Status = "dns_only"
	} else {
		r.Status = "dead"
	}
	return r
}

func (c *Checker) checkDNS(ctx context.Context, domain string, r *SiteRecord) {
	dnsCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// A/AAAA records
	ips, err := c.resolver.LookupHost(dnsCtx, domain)
	if err != nil {
		r.DNSError = err.Error()
		return
	}
	if len(ips) > 0 {
		r.DNSAlive = true
		r.DNSIPs = strings.Join(ips, ",")
	}

	// CNAME
	cname, err := c.resolver.LookupCNAME(dnsCtx, domain)
	if err == nil && cname != "" && cname != domain+"." {
		r.DNSCnames = strings.TrimSuffix(cname, ".")
	}

	// MX records
	mxs, err := c.resolver.LookupMX(dnsCtx, domain)
	if err == nil && len(mxs) > 0 {
		var mxList []string
		for _, mx := range mxs {
			mxList = append(mxList, strings.TrimSuffix(mx.Host, "."))
		}
		r.DNSMX = strings.Join(mxList, ",")
	}

	// NS records
	nss, err := c.resolver.LookupNS(dnsCtx, domain)
	if err == nil && len(nss) > 0 {
		var nsList []string
		for _, ns := range nss {
			nsList = append(nsList, strings.TrimSuffix(ns.Host, "."))
		}
		r.DNSNS = strings.Join(nsList, ",")
	}
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

func (c *Checker) checkHTTP(ctx context.Context, domain string, r *SiteRecord) {
	// Per-request redirect chain tracking
	var redirectChain []string
	client := &http.Client{
		Timeout:   c.timeout,
		Transport: c.httpClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			redirectChain = append(redirectChain, req.URL.String())
			return nil
		},
	}

	// Try HTTPS first, then HTTP
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + domain
		redirectChain = nil // reset for each scheme attempt

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)

		if err != nil {
			r.HTTPError = err.Error()
			continue
		}

		r.HTTPAlive = true
		r.HTTPStatus = resp.StatusCode
		r.HTTPRespMs = elapsed.Milliseconds()
		r.HTTPServer = resp.Header.Get("Server")

		// v2: Expanded header collection
		r.HTTPContentType = resp.Header.Get("Content-Type")
		r.HTTPPoweredBy = resp.Header.Get("X-Powered-By")
		r.HTTPVia = resp.Header.Get("Via")
		r.HTTPCacheControl = resp.Header.Get("Cache-Control")
		r.HTTPXFrame = resp.Header.Get("X-Frame-Options")
		r.HTTPHSTS = resp.Header.Get("Strict-Transport-Security")

		// Final redirect destination
		if resp.Request.URL.String() != url {
			r.HTTPRedirect = resp.Request.URL.String()
		}

		// v2: Redirect chain
		if len(redirectChain) > 0 {
			r.HTTPRedirectChain = strings.Join(redirectChain, " -> ")
		}

		// v2: Rich SSL certificate data
		if resp.TLS != nil {
			r.HTTPTLS = true
			if len(resp.TLS.PeerCertificates) > 0 {
				cert := resp.TLS.PeerCertificates[0]
				if len(cert.Issuer.Organization) > 0 {
					r.HTTPTLSIssuer = cert.Issuer.Organization[0]
				}
				r.HTTPTLSCN = cert.Subject.CommonName
				r.HTTPTLSExpiry = cert.NotAfter.Format("2006-01-02")
				r.HTTPTLSDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
				// Self-signed detection: issuer CN matches subject CN
				if cert.Issuer.CommonName != "" && cert.Issuer.CommonName == cert.Subject.CommonName {
					r.HTTPTLSSelfSigned = true
				}
			}
		} else if scheme == "https" {
			r.HTTPTLS = false
		}

		// Read body for title (limit 64KB)
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if err == nil {
			if m := titleRegex.FindSubmatch(body); len(m) > 1 {
				title := strings.TrimSpace(string(m[1]))
				if len(title) > 200 {
					title = title[:200]
				}
				r.HTTPTitle = title
			}
		}
		return // success on first working scheme
	}
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "www.")
	d = strings.TrimSuffix(d, "/")
	return strings.ToLower(d)
}

// ════════════════════════════════════════════════════════════════
// TARGET FILE LOADING
// ════════════════════════════════════════════════════════════════

func loadTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := cleanDomain(line)
		if domain != "" && !seen[domain] {
			seen[domain] = true
			targets = append(targets, domain)
		}
	}
	return targets, nil
}

func scanTargetFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files
}

// ════════════════════════════════════════════════════════════════
// PATH SANITIZATION
// ════════════════════════════════════════════════════════════════

func sanitizePath(raw string) string {
	s := raw
	// Strip ANSI escape codes
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	s = ansi.ReplaceAllString(s, "")
	// Strip bracketed paste
	s = strings.ReplaceAll(s, "\x1b[200~", "")
	s = strings.ReplaceAll(s, "\x1b[201~", "")
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	s = strings.TrimSpace(s)
	if !filepath.IsAbs(s) {
		if abs, err := filepath.Abs(s); err == nil {
			s = abs
		}
	}
	return s
}

// ════════════════════════════════════════════════════════════════
// TUI - STATE TYPES
// ════════════════════════════════════════════════════════════════

type CommandState int

const (
	StateMenu CommandState = iota
	StateInput
	StateSelect
	StateRunning
	StateComplete
	StateViewResults
)

type InputMode int

const (
	InputNone InputMode = iota
	InputDomain
	InputFile
	InputExport
)

type MenuItem struct {
	Key   string
	Label string
}

var menuItems = []MenuItem{
	{"1", "Check Single Domain"},
	{"2", "Bulk Scan from targets/"},
	{"3", "Bulk Scan from File Path"},
	{"4", "View Alive Sites"},
	{"5", "View DNS-Only Sites"},
	{"6", "View Dead Sites"},
	{"7", "Export Results to CSV"},
	{"8", "DB Statistics"},
	{"9", "Rescan All (Refresh)"},
	{"0", "Exit"},
}

// ════════════════════════════════════════════════════════════════
// TUI - MAIN STRUCT
// ════════════════════════════════════════════════════════════════

type TUI struct {
	screen tcell.Screen
	width  int
	height int

	commandState CommandState
	inputMode    InputMode
	menuIndex    int

	inputBuffer string
	inputPrompt string
	inputCursor int

	selectItems []string
	selectPaths []string
	selectIndex int

	outputLines  []string
	outputScroll int
	outputMutex  sync.Mutex
	renderMutex  sync.Mutex

	db      *DB
	checker *Checker
	dbPath  string
	logsDir string
	logFile *os.File

	scanned int64
	alive   int64
	dnsOnly int64
	dead    int64

	cancelScan context.CancelFunc

	showSplash   bool
	splashPhase  int // 0 = main logo, 1 = dedication
	splashStart  time.Time
	running      bool

	viewLines []string
	viewTitle string
	viewScroll int
}

func NewTUI(dbPath string, timeout time.Duration) (*TUI, error) {
	db, err := NewDB(dbPath)
	if err != nil {
		return nil, err
	}
	screen, err := tcell.NewScreen()
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := screen.Init(); err != nil {
		db.Close()
		return nil, err
	}
	screen.SetStyle(tcell.StyleDefault.Background(ColorBackground).Foreground(ColorText))
	screen.EnableMouse()
	screen.Clear()

	w, h := screen.Size()
	logsDir := filepath.Join(filepath.Dir(dbPath), "logs")
	os.MkdirAll(logsDir, 0755)

	return &TUI{
		screen:      screen,
		width:       w,
		height:      h,
		commandState: StateMenu,
		db:          db,
		checker:     NewChecker(timeout),
		dbPath:      dbPath,
		logsDir:     logsDir,
		showSplash:  true,
		splashStart: time.Now(),
		running:     true,
	}, nil
}

func (tui *TUI) Close() {
	tui.screen.Fini()
	if tui.logFile != nil {
		tui.logFile.Close()
	}
	tui.db.Close()
}

// ════════════════════════════════════════════════════════════════
// TUI - DRAWING PRIMITIVES
// ════════════════════════════════════════════════════════════════

func (tui *TUI) drawString(x, y int, text string, style tcell.Style) {
	for _, r := range text {
		if x >= tui.width {
			break
		}
		tui.screen.SetContent(x, y, r, nil, style)
		x += runeWidth(r)
	}
}

func runeWidth(r rune) int {
	if !utf8.ValidRune(r) {
		return 0
	}
	return runewidth.RuneWidth(r)
}

// displayWidth returns the visual column width of a string.
func displayWidth(s string) int {
	return runewidth.StringWidth(s)
}


// truncateToWidth truncates a string to fit within maxWidth display columns,
// appending suffix (e.g. "...") if truncated. Safe for multi-byte UTF-8.
func truncateToWidth(s string, maxWidth int, suffix string) string {
	sw := displayWidth(s)
	if sw <= maxWidth {
		return s
	}
	suffixW := displayWidth(suffix)
	target := maxWidth - suffixW
	if target <= 0 {
		return suffix[:maxWidth]
	}
	w := 0
	for i, r := range s {
		rw := runewidth.RuneWidth(r)
		if w+rw > target {
			return s[:i] + suffix
		}
		w += rw
	}
	return s
}

func (tui *TUI) drawBox(x, y, w, h int, title string, style tcell.Style) {
	// Corners
	tui.screen.SetContent(x, y, '┌', nil, style)
	tui.screen.SetContent(x+w-1, y, '┐', nil, style)
	tui.screen.SetContent(x, y+h-1, '└', nil, style)
	tui.screen.SetContent(x+w-1, y+h-1, '┘', nil, style)
	// Horizontal
	for i := x + 1; i < x+w-1; i++ {
		tui.screen.SetContent(i, y, '─', nil, style)
		tui.screen.SetContent(i, y+h-1, '─', nil, style)
	}
	// Vertical
	for i := y + 1; i < y+h-1; i++ {
		tui.screen.SetContent(x, i, '│', nil, style)
		tui.screen.SetContent(x+w-1, i, '│', nil, style)
	}
	// Title
	if title != "" {
		t := " " + title + " "
		tui.drawString(x+2, y, t, style.Bold(true))
	}
}

func (tui *TUI) fillRect(x, y, w, h int, style tcell.Style) {
	for row := y; row < y+h && row < tui.height; row++ {
		for col := x; col < x+w && col < tui.width; col++ {
			tui.screen.SetContent(col, row, ' ', nil, style)
		}
	}
}

// ════════════════════════════════════════════════════════════════
// TUI - SPLASH SCREEN
// ════════════════════════════════════════════════════════════════

var splashLogo = []string{
	`  _____ ____      _    _   _ _  _______ _   _ ____ _____ _____ ___ _   _`,
	` |  ___|  _ \    / \  | \ | | |/ / ____| \ | / ___|_   _| ____|_ _| \ | |`,
	` | |_  | |_) |  / _ \ |  \| | ' /|  _| |  \| \___ \ | | |  _|  | ||  \| |`,
	` |  _| |  _ <  / ___ \| |\  | . \| |___| |\  |___) || | | |___ | || |\  |`,
	` |_|   |_| \_\/_/   \_\_| \_|_|\_\_____|_| \_|____/ |_| |_____|___|_| \_|`,
}

func (tui *TUI) renderSplash() {
	elapsed := time.Since(tui.splashStart).Seconds()

	if tui.splashPhase == 0 {
		// Phase 0: Main logo
		if elapsed > 2.5 {
			tui.splashPhase = 1
			tui.splashStart = time.Now()
			return
		}

		tui.fillRect(0, 0, tui.width, tui.height, tcell.StyleDefault.Background(ColorBackground))

		logoStyle := tcell.StyleDefault.Foreground(ColorLogo).Background(ColorBackground).Bold(true)
		boltStyle := tcell.StyleDefault.Foreground(ColorBolt).Background(ColorBackground).Bold(true)

		startY := tui.height/2 - 5
		for i, line := range splashLogo {
			charCount := int(elapsed * 60)
			visible := line
			if charCount < len(line) {
				visible = line[:charCount]
			}
			x := (tui.width - len(line)) / 2
			if x < 0 {
				x = 0
			}
			tui.drawString(x, startY+i, visible, logoStyle)
		}

		if elapsed > 1.0 {
			bolt := ">> IT'S ALIVE! <<"
			x := (tui.width - displayWidth(bolt)) / 2
			tui.drawString(x, startY+7, bolt, boltStyle)
		}
		if elapsed > 1.5 {
			sub := fmt.Sprintf("v%s -- Dual Phenomenology Site Checker", version)
			x := (tui.width - displayWidth(sub)) / 2
			tui.drawString(x, startY+9, sub, tcell.StyleDefault.Foreground(ColorDim).Background(ColorBackground))
		}
	} else {
		// Phase 1: Dedication easter egg with dissolve effect
		totalDuration := 5.0
		dissolveStart := 3.5

		if elapsed > totalDuration {
			tui.showSplash = false
			return
		}

		tui.fillRect(0, 0, tui.width, tui.height, tcell.StyleDefault.Background(ColorBackground))

		dimStyle := tcell.StyleDefault.Foreground(ColorDim).Background(ColorBackground)
		nameStyle := tcell.StyleDefault.Foreground(ColorBolt).Background(ColorBackground).Bold(true)
		heartStyle := tcell.StyleDefault.Foreground(ColorDanger).Background(ColorBackground).Bold(true)

		centerY := tui.height / 2

		// Dissolve characters: as time progresses past dissolveStart, randomly replace chars with falling fragments
		dissolving := elapsed > dissolveStart
		dissolveProgress := 0.0
		if dissolving {
			dissolveProgress = (elapsed - dissolveStart) / (totalDuration - dissolveStart)
		}
		fragments := []rune{'·', '.', ':', '°', ' ', ' ', ' '}

		drawDissolving := func(x, y int, text string, style tcell.Style) {
			for i, r := range text {
				if dissolving {
					// Hash-based pseudo-random per character position
					hash := (x + i*7 + y*13 + int(elapsed*10)) % 10
					threshold := int(dissolveProgress * 10)
					if hash < threshold {
						// Character has dissolved — show a falling fragment or blank
						fragIdx := (hash + int(elapsed*5)) % len(fragments)
						dropY := y + int(dissolveProgress*float64(tui.height-y)*float64(hash+1)/10.0)
						if dropY < tui.height && fragments[fragIdx] != ' ' {
							fadedStyle := tcell.StyleDefault.Foreground(ColorDim).Background(ColorBackground)
							tui.screen.SetContent(x+i, dropY, fragments[fragIdx], nil, fadedStyle)
						}
						tui.screen.SetContent(x+i, y, ' ', nil, style)
						continue
					}
				}
				tui.screen.SetContent(x+i, y, r, nil, style)
			}
		}

		if elapsed > 0.3 {
			line1 := "this is for"
			x := (tui.width - displayWidth(line1)) / 2
			drawDissolving(x, centerY-1, line1, dimStyle)
		}
		if elapsed > 0.8 {
			line2 := "_m0usem0use_  &  ziggy"
			x := (tui.width - displayWidth(line2)) / 2
			drawDissolving(x, centerY+1, line2, nameStyle)
		}
		if elapsed > 1.5 {
			heart := "<3"
			x := (tui.width - displayWidth(heart)) / 2
			drawDissolving(x, centerY+3, heart, heartStyle)
		}
	}
}

// ════════════════════════════════════════════════════════════════
// TUI - DASHBOARD RENDERING
// ════════════════════════════════════════════════════════════════

func (tui *TUI) render() {
	tui.renderMutex.Lock()
	defer tui.renderMutex.Unlock()

	tui.screen.Clear()
	tui.width, tui.height = tui.screen.Size()

	if tui.showSplash {
		tui.renderSplash()
		tui.screen.Show()
		return
	}

	if tui.commandState == StateViewResults {
		tui.renderViewResults()
		tui.screen.Show()
		return
	}

	borderStyle := tcell.StyleDefault.Foreground(ColorBorder).Background(ColorBackground)
	textStyle := tcell.StyleDefault.Foreground(ColorText).Background(ColorBackground)
	primaryStyle := tcell.StyleDefault.Foreground(ColorPrimary).Background(ColorBackground)
	dimStyle := tcell.StyleDefault.Foreground(ColorDim).Background(ColorBackground)

	// Title bar
	title := fmt.Sprintf(" >> FRANKENSTEIN v%s ", version)
	tui.drawString(1, 0, title, primaryStyle.Bold(true))

	// Status bar at bottom
	stats := tui.db.GetStats()
	statusLine := fmt.Sprintf(" DB: %s | Total: %d | Alive: %d | DNS-Only: %d | Dead: %d | HTTPS: %d ",
		filepath.Base(tui.dbPath), stats.Total, stats.Alive, stats.DNSOnly, stats.Dead, stats.HTTPSites)
	tui.fillRect(0, tui.height-1, tui.width, 1, tcell.StyleDefault.Background(ColorBorder).Foreground(ColorText))
	tui.drawString(0, tui.height-1, statusLine, tcell.StyleDefault.Background(ColorBorder).Foreground(ColorText))

	// Layout: left panel (menu) = 50 chars, right panel (output) = rest
	leftW := 50
	if tui.width < 80 {
		leftW = tui.width / 2
	}
	rightW := tui.width - leftW - 1
	panelH := tui.height - 5

	// Left panel - Menu
	tui.drawBox(0, 1, leftW, panelH, "MENU", borderStyle)
	y := 3
	for i, item := range menuItems {
		style := textStyle
		if i == tui.menuIndex {
			tui.fillRect(2, y, leftW-4, 1, tcell.StyleDefault.Background(ColorPrimary).Foreground(ColorBackground))
			style = tcell.StyleDefault.Background(ColorPrimary).Foreground(ColorBackground).Bold(true)
		}
		label := fmt.Sprintf(" [%s] %s", item.Key, item.Label)
		tui.drawString(2, y, label, style)
		y++
	}

	// Scan modes info
	y += 1
	tui.drawString(3, y, "── Dual Phenomenology v2 ──", dimStyle)
	y++
	tui.drawString(3, y, "P1: DNS Resolution", primaryStyle)
	y++
	tui.drawString(3, y, "   A/AAAA, CNAME, MX, NS", dimStyle)
	y++
	tui.drawString(3, y, "P2: HTTP/S Probe", primaryStyle)
	y++
	tui.drawString(3, y, "   Status, Title, TLS Cert, Headers", dimStyle)
	y++
	tui.drawString(3, y, fmt.Sprintf("   %d concurrent workers", maxWorkers), dimStyle)
	y++
	tui.drawString(3, y, "   Retry pass + Percentiles", dimStyle)

	// Right panel - Output
	tui.drawBox(leftW, 1, rightW+1, panelH, "OUTPUT", borderStyle)
	tui.outputMutex.Lock()
	lines := tui.outputLines
	maxLines := panelH - 2
	startIdx := 0
	if len(lines) > maxLines {
		startIdx = len(lines) - maxLines + tui.outputScroll
		if startIdx < 0 {
			startIdx = 0
		}
		if startIdx > len(lines)-maxLines {
			startIdx = len(lines) - maxLines
		}
	}
	for i := 0; i < maxLines && startIdx+i < len(lines); i++ {
		line := lines[startIdx+i]
		lineStyle := textStyle
		if strings.HasPrefix(line, "[+]") || strings.Contains(line, "ALIVE") {
			lineStyle = tcell.StyleDefault.Foreground(ColorSuccess).Background(ColorBackground)
		} else if strings.HasPrefix(line, "[-]") || strings.Contains(line, "DEAD") {
			lineStyle = tcell.StyleDefault.Foreground(ColorDanger).Background(ColorBackground)
		} else if strings.HasPrefix(line, "[*]") {
			lineStyle = tcell.StyleDefault.Foreground(ColorInfo).Background(ColorBackground)
		} else if strings.HasPrefix(line, "[!]") || strings.Contains(line, "DNS-ONLY") {
			lineStyle = tcell.StyleDefault.Foreground(ColorWarning).Background(ColorBackground)
		} else if strings.HasPrefix(line, "[~]") {
			lineStyle = dimStyle
		}
		// Truncate to panel width (rune-safe)
		maxW := rightW - 3
		if displayWidth(line) > maxW {
			line = truncateToWidth(line, maxW, "")
		}
		tui.drawString(leftW+2, 3+i, line, lineStyle)
	}
	tui.outputMutex.Unlock()

	// Bottom - input area or scan progress
	inputY := tui.height - 4
	tui.drawBox(0, inputY, tui.width, 3, "", borderStyle)

	switch tui.commandState {
	case StateMenu:
		hint := " Navigate: ↑↓  Select: Enter  Quit: Esc/Q "
		tui.drawString(2, inputY+1, hint, dimStyle)

	case StateInput:
		prompt := tui.inputPrompt + ": "
		tui.drawString(2, inputY+1, prompt, primaryStyle)
		tui.drawString(2+len(prompt), inputY+1, tui.inputBuffer, textStyle)
		// Cursor
		cursorX := 2 + len(prompt) + tui.inputCursor
		if cursorX < tui.width-2 {
			tui.screen.ShowCursor(cursorX, inputY+1)
		}

	case StateSelect:
		hint := " ↑↓ Navigate  Enter: Select  Esc: Cancel "
		tui.drawString(2, inputY+1, hint, dimStyle)
		// Draw file picker in right panel
		tui.renderFilePicker(leftW+2, 3, rightW-3, panelH-2)

	case StateRunning:
		progress := fmt.Sprintf(" [%d workers] Done: %d | Alive: %d | DNS: %d | Dead: %d  [ESC cancel]",
			maxWorkers, atomic.LoadInt64(&tui.scanned), atomic.LoadInt64(&tui.alive),
			atomic.LoadInt64(&tui.dnsOnly), atomic.LoadInt64(&tui.dead))
		tui.drawString(2, inputY+1, progress, primaryStyle)

	case StateComplete:
		hint := " Scan complete. Press any key to return to menu. "
		tui.drawString(2, inputY+1, hint, tcell.StyleDefault.Foreground(ColorSuccess).Background(ColorBackground))
	}

	tui.screen.Show()
}

func (tui *TUI) renderFilePicker(x, y, w, h int) {
	textStyle := tcell.StyleDefault.Foreground(ColorText).Background(ColorBackground)
	for i := 0; i < h && i < len(tui.selectItems); i++ {
		style := textStyle
		if i == tui.selectIndex {
			tui.fillRect(x-1, y+i, w+1, 1, tcell.StyleDefault.Background(ColorPrimary))
			style = tcell.StyleDefault.Background(ColorPrimary).Foreground(ColorBackground).Bold(true)
		}
		name := tui.selectItems[i]
		if len(name) > w {
			name = name[:w]
		}
		tui.drawString(x, y+i, name, style)
	}
}

func (tui *TUI) renderViewResults() {
	borderStyle := tcell.StyleDefault.Foreground(ColorBorder).Background(ColorBackground)
	textStyle := tcell.StyleDefault.Foreground(ColorText).Background(ColorBackground)
	dimStyle := tcell.StyleDefault.Foreground(ColorDim).Background(ColorBackground)

	tui.drawBox(0, 0, tui.width, tui.height-2, tui.viewTitle, borderStyle)

	maxLines := tui.height - 5
	startIdx := tui.viewScroll
	if startIdx > len(tui.viewLines)-maxLines {
		startIdx = len(tui.viewLines) - maxLines
	}
	if startIdx < 0 {
		startIdx = 0
	}

	for i := 0; i < maxLines && startIdx+i < len(tui.viewLines); i++ {
		line := tui.viewLines[startIdx+i]
		style := textStyle
		if strings.HasPrefix(line, "  ") {
			style = dimStyle
		}
		if len(line) > tui.width-4 {
			line = line[:tui.width-4]
		}
		tui.drawString(2, 2+i, line, style)
	}

	hint := fmt.Sprintf(" ↑↓/PgUp/PgDn: Scroll | Esc: Back | Showing %d entries ", len(tui.viewLines))
	tui.fillRect(0, tui.height-2, tui.width, 1, tcell.StyleDefault.Background(ColorBorder).Foreground(ColorText))
	tui.drawString(0, tui.height-2, hint, tcell.StyleDefault.Background(ColorBorder).Foreground(ColorText))
}

// ════════════════════════════════════════════════════════════════
// TUI - OUTPUT HELPERS
// ════════════════════════════════════════════════════════════════

func (tui *TUI) addOutput(line string) {
	tui.outputMutex.Lock()
	tui.outputLines = append(tui.outputLines, line)
	tui.outputScroll = 0 // auto-scroll to bottom
	tui.outputMutex.Unlock()
	if tui.logFile != nil {
		fmt.Fprintln(tui.logFile, line)
	}
}

func (tui *TUI) clearOutput() {
	tui.outputMutex.Lock()
	tui.outputLines = nil
	tui.outputScroll = 0
	tui.outputMutex.Unlock()
}

func (tui *TUI) openLog(prefix string) {
	ts := time.Now().Format("2006-01-02_150405")
	name := fmt.Sprintf("%s_%s.log", prefix, ts)
	f, err := os.Create(filepath.Join(tui.logsDir, name))
	if err == nil {
		tui.logFile = f
	}
}

func (tui *TUI) closeLog() {
	if tui.logFile != nil {
		tui.logFile.Close()
		tui.logFile = nil
	}
}

// ════════════════════════════════════════════════════════════════
// TUI - TARGET FILE DISCOVERY
// ════════════════════════════════════════════════════════════════

func (tui *TUI) refreshTargetFiles() {
	var allFiles []string
	seen := make(map[string]bool)

	candidates := []string{
		filepath.Join(filepath.Dir(tui.dbPath), "targets"),
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "targets"))
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates, filepath.Join(exeDir, "targets"))
		candidates = append(candidates, filepath.Join(filepath.Dir(exeDir), "targets"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "Documents", "recon-suite", "Frankenstein", "targets"))
	}

	for _, dir := range candidates {
		for _, f := range scanTargetFiles(dir) {
			if !seen[f] {
				seen[f] = true
				allFiles = append(allFiles, f)
			}
		}
	}

	sort.Strings(allFiles)
	tui.selectPaths = allFiles
	tui.selectItems = make([]string, len(allFiles))
	for i, f := range allFiles {
		tui.selectItems[i] = filepath.Base(f)
	}
	tui.selectIndex = 0
}

// ════════════════════════════════════════════════════════════════
// TUI - SCAN LOGIC
// ════════════════════════════════════════════════════════════════

func (tui *TUI) runSingleScan(domain string) {
	tui.commandState = StateRunning
	tui.clearOutput()
	tui.openLog("single")

	domain = cleanDomain(domain)
	tui.addOutput(fmt.Sprintf("[*] Checking domain: %s", domain))
	tui.addOutput("[*] ── Phenomenon 1: DNS Resolution ──")

	ctx, cancel := context.WithCancel(context.Background())
	tui.cancelScan = cancel

	go func() {
		defer cancel()
		defer tui.closeLog()

		result := tui.checker.Check(ctx, domain)

		// DNS results
		if result.DNSAlive {
			tui.addOutput(fmt.Sprintf("[+] DNS: ALIVE -- IPs: %s", result.DNSIPs))
			if result.DNSCnames != "" {
				tui.addOutput(fmt.Sprintf("[~]   CNAME: %s", result.DNSCnames))
			}
			if result.DNSMX != "" {
				tui.addOutput(fmt.Sprintf("[~]   MX: %s", result.DNSMX))
			}
			if result.DNSNS != "" {
				tui.addOutput(fmt.Sprintf("[~]   NS: %s", result.DNSNS))
			}
		} else {
			tui.addOutput(fmt.Sprintf("[-] DNS: DEAD --%s", result.DNSError))
		}

		tui.addOutput("[*] ── Phenomenon 2: HTTP/S Probe ──")
		if result.HTTPAlive {
			scheme := "HTTP"
			if result.HTTPTLS {
				scheme = "HTTPS"
			}
			tui.addOutput(fmt.Sprintf("[+] %s: ALIVE -- Status %d (%dms)", scheme, result.HTTPStatus, result.HTTPRespMs))
			if result.HTTPTitle != "" {
				tui.addOutput(fmt.Sprintf("[~]   Title: %s", result.HTTPTitle))
			}
			if result.HTTPServer != "" {
				tui.addOutput(fmt.Sprintf("[~]   Server: %s", result.HTTPServer))
			}
			if result.HTTPPoweredBy != "" {
				tui.addOutput(fmt.Sprintf("[~]   X-Powered-By: %s", result.HTTPPoweredBy))
			}
			if result.HTTPContentType != "" {
				tui.addOutput(fmt.Sprintf("[~]   Content-Type: %s", result.HTTPContentType))
			}
			if result.HTTPXFrame != "" {
				tui.addOutput(fmt.Sprintf("[~]   X-Frame-Options: %s", result.HTTPXFrame))
			}
			if result.HTTPHSTS != "" {
				tui.addOutput(fmt.Sprintf("[~]   HSTS: %s", result.HTTPHSTS))
			}
			if result.HTTPCacheControl != "" {
				tui.addOutput(fmt.Sprintf("[~]   Cache-Control: %s", result.HTTPCacheControl))
			}
			if result.HTTPVia != "" {
				tui.addOutput(fmt.Sprintf("[~]   Via: %s", result.HTTPVia))
			}
			if result.HTTPRedirect != "" {
				tui.addOutput(fmt.Sprintf("[~]   Redirect: %s", result.HTTPRedirect))
			}
			if result.HTTPRedirectChain != "" {
				tui.addOutput(fmt.Sprintf("[~]   Chain: %s", result.HTTPRedirectChain))
			}
			if result.HTTPTLS {
				tui.addOutput("[*] ── TLS Certificate ──")
				if result.HTTPTLSIssuer != "" {
					tui.addOutput(fmt.Sprintf("[~]   Issuer: %s", result.HTTPTLSIssuer))
				}
				if result.HTTPTLSCN != "" {
					tui.addOutput(fmt.Sprintf("[~]   Subject CN: %s", result.HTTPTLSCN))
				}
				if result.HTTPTLSExpiry != "" {
					daysMsg := fmt.Sprintf("%d days", result.HTTPTLSDaysLeft)
					if result.HTTPTLSDaysLeft <= 30 {
						daysMsg = fmt.Sprintf("%d days [!] EXPIRING SOON", result.HTTPTLSDaysLeft)
					}
					if result.HTTPTLSDaysLeft <= 0 {
						daysMsg = fmt.Sprintf("%d days [!] EXPIRED", result.HTTPTLSDaysLeft)
					}
					tui.addOutput(fmt.Sprintf("[~]   Expires: %s (%s)", result.HTTPTLSExpiry, daysMsg))
				}
				if result.HTTPTLSSelfSigned {
					tui.addOutput("[!]   ** SELF-SIGNED CERTIFICATE **")
				}
			}
		} else {
			tui.addOutput(fmt.Sprintf("[-] HTTP: DEAD --%s", result.HTTPError))
		}

		tui.addOutput("")
		switch result.Status {
		case "alive":
			tui.addOutput("[+] >> VERDICT: IT'S ALIVE!")
		case "dns_only":
			tui.addOutput("[!] >> VERDICT: DNS-ONLY (resolves but no HTTP)")
		case "dead":
			tui.addOutput("[-] >> VERDICT: DEAD (no DNS, no HTTP)")
		}

		tui.db.UpsertSite(result)
		atomic.AddInt64(&tui.scanned, 1)

		tui.commandState = StateComplete
	}()
}

// percentile returns the value at percentile p (0.0-1.0) from a sorted slice.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func (tui *TUI) runBulkScan(filePath string) {
	tui.commandState = StateRunning
	tui.clearOutput()
	tui.openLog("bulk")

	atomic.StoreInt64(&tui.scanned, 0)
	atomic.StoreInt64(&tui.alive, 0)
	atomic.StoreInt64(&tui.dnsOnly, 0)
	atomic.StoreInt64(&tui.dead, 0)

	targets, err := loadTargets(filePath)
	if err != nil {
		tui.addOutput(fmt.Sprintf("[-] Failed to load targets: %v", err))
		tui.commandState = StateComplete
		return
	}
	total := len(targets)
	tui.addOutput(fmt.Sprintf("[*] Loaded %d targets from %s", total, filepath.Base(filePath)))
	tui.addOutput(fmt.Sprintf("[*] Starting concurrent scan (%d workers)...", maxWorkers))
	tui.addOutput("")

	ctx, cancel := context.WithCancel(context.Background())
	tui.cancelScan = cancel

	go func() {
		defer cancel()
		defer tui.closeLog()

		var aliveCount, dnsOnlyCount, deadCount int64
		var mu sync.Mutex
		var failedDomains []string
		var responseTimes []int64

		// ── PASS 1: Concurrent scan with worker pool ──
		sem := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup

		for _, domain := range targets {
			select {
			case <-ctx.Done():
				break
			default:
			}

			sem <- struct{}{} // acquire worker slot
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }() // release worker slot

				select {
				case <-ctx.Done():
					return
				default:
				}

				result := tui.checker.Check(ctx, d)
				tui.db.UpsertSite(result)
				n := atomic.AddInt64(&tui.scanned, 1)

				switch result.Status {
				case "alive":
					atomic.AddInt64(&aliveCount, 1)
					atomic.AddInt64(&tui.alive, 1)
					extra := ""
					if result.HTTPTitle != "" {
						extra = fmt.Sprintf(" -- \"%s\"", result.HTTPTitle)
						extra = truncateToWidth(extra, 60, "...")
					}
					tui.addOutput(fmt.Sprintf("[+] (%d/%d) %s ALIVE %d %dms%s", n, total, d, result.HTTPStatus, result.HTTPRespMs, extra))
					mu.Lock()
					responseTimes = append(responseTimes, result.HTTPRespMs)
					mu.Unlock()
				case "dns_only":
					atomic.AddInt64(&dnsOnlyCount, 1)
					atomic.AddInt64(&tui.dnsOnly, 1)
					tui.addOutput(fmt.Sprintf("[!] (%d/%d) %s DNS-ONLY -- IPs: %s", n, total, d, result.DNSIPs))
				case "dead":
					atomic.AddInt64(&deadCount, 1)
					atomic.AddInt64(&tui.dead, 1)
					tui.addOutput(fmt.Sprintf("[-] (%d/%d) %s DEAD", n, total, d))
					mu.Lock()
					failedDomains = append(failedDomains, d)
					mu.Unlock()
				default:
					atomic.AddInt64(&deadCount, 1)
					atomic.AddInt64(&tui.dead, 1)
					tui.addOutput(fmt.Sprintf("[-] (%d/%d) %s ERROR: %s", n, total, d, result.HTTPError))
					mu.Lock()
					failedDomains = append(failedDomains, d)
					mu.Unlock()
				}
			}(domain)
		}
		wg.Wait()

		// Check for cancellation before retry
		select {
		case <-ctx.Done():
			tui.addOutput("")
			tui.addOutput("[!] Scan cancelled by user")
			goto summary
		default:
		}

		// ── PASS 2: Retry failed domains with 3x timeout ──
		if len(failedDomains) > 0 {
			tui.addOutput("")
			tui.addOutput(fmt.Sprintf("[*] ── RETRY PASS: %d failed domains (3x timeout) ──", len(failedDomains)))
			retryChecker := NewChecker(tui.checker.timeout * 3)
			var retryRecovered int64

			for _, domain := range failedDomains {
				select {
				case <-ctx.Done():
					tui.addOutput("[!] Retry cancelled by user")
					goto summary
				default:
				}

				sem <- struct{}{}
				wg.Add(1)
				go func(d string) {
					defer wg.Done()
					defer func() { <-sem }()

					select {
					case <-ctx.Done():
						return
					default:
					}

					result := retryChecker.Check(ctx, d)
					if result.Status == "alive" || result.Status == "dns_only" {
						tui.db.UpsertSite(result)
						recovered := atomic.AddInt64(&retryRecovered, 1)
						if result.Status == "alive" {
							atomic.AddInt64(&aliveCount, 1)
							atomic.AddInt64(&deadCount, -1)
							atomic.AddInt64(&tui.alive, 1)
							atomic.AddInt64(&tui.dead, -1)
							mu.Lock()
							responseTimes = append(responseTimes, result.HTTPRespMs)
							mu.Unlock()
							tui.addOutput(fmt.Sprintf("[+] RETRY %d: %s RECOVERED -- ALIVE %d", recovered, d, result.HTTPStatus))
						} else {
							atomic.AddInt64(&dnsOnlyCount, 1)
							atomic.AddInt64(&deadCount, -1)
							atomic.AddInt64(&tui.dnsOnly, 1)
							atomic.AddInt64(&tui.dead, -1)
							tui.addOutput(fmt.Sprintf("[!] RETRY %d: %s RECOVERED -- DNS-ONLY", recovered, d))
						}
					}
				}(domain)
			}
			wg.Wait()

			recovered := atomic.LoadInt64(&retryRecovered)
			if recovered > 0 {
				tui.addOutput(fmt.Sprintf("[+] Retry recovered %d domains!", recovered))
			} else {
				tui.addOutput("[~] Retry pass: no additional recoveries")
			}
		}

	summary:
		// ── Response time percentiles ──
		sort.Slice(responseTimes, func(i, j int) bool { return responseTimes[i] < responseTimes[j] })

		tui.addOutput("")
		tui.addOutput("[*] ═══════════════════════════════════")
		tui.addOutput("[*]  >> FRANKENSTEIN SCAN COMPLETE <<")
		tui.addOutput("[*] ═══════════════════════════════════")
		tui.addOutput(fmt.Sprintf("[*]  Scanned:  %d sites (%d workers)", total, maxWorkers))
		tui.addOutput(fmt.Sprintf("[+]  Alive:    %d sites", atomic.LoadInt64(&aliveCount)))
		tui.addOutput(fmt.Sprintf("[!]  DNS-Only: %d sites", atomic.LoadInt64(&dnsOnlyCount)))
		tui.addOutput(fmt.Sprintf("[-]  Dead:     %d sites", atomic.LoadInt64(&deadCount)))
		ac := atomic.LoadInt64(&aliveCount)
		alivePercent := 0.0
		if total > 0 {
			alivePercent = float64(ac) / float64(total) * 100
		}
		tui.addOutput(fmt.Sprintf("[*]  Alive %%:  %.1f%%", alivePercent))

		if len(responseTimes) > 0 {
			tui.addOutput("")
			tui.addOutput("[*] ── Response Time Percentiles ──")
			tui.addOutput(fmt.Sprintf("[*]  p50 (median): %dms", percentile(responseTimes, 0.50)))
			tui.addOutput(fmt.Sprintf("[*]  p90:          %dms", percentile(responseTimes, 0.90)))
			tui.addOutput(fmt.Sprintf("[*]  p95:          %dms", percentile(responseTimes, 0.95)))
			tui.addOutput(fmt.Sprintf("[*]  Fastest:      %dms", responseTimes[0]))
			tui.addOutput(fmt.Sprintf("[*]  Slowest:      %dms", responseTimes[len(responseTimes)-1]))
		}

		tui.commandState = StateComplete
	}()
}

func (tui *TUI) runRescanAll() {
	tui.commandState = StateRunning
	tui.clearOutput()
	tui.openLog("rescan")

	atomic.StoreInt64(&tui.scanned, 0)
	atomic.StoreInt64(&tui.alive, 0)
	atomic.StoreInt64(&tui.dnsOnly, 0)
	atomic.StoreInt64(&tui.dead, 0)

	rows, err := tui.db.conn.Query("SELECT domain FROM sites ORDER BY domain")
	if err != nil {
		tui.addOutput(fmt.Sprintf("[-] DB error: %v", err))
		tui.commandState = StateComplete
		return
	}
	var domains []string
	for rows.Next() {
		var d string
		rows.Scan(&d)
		domains = append(domains, d)
	}
	rows.Close()

	if len(domains) == 0 {
		tui.addOutput("[!] No domains in database to rescan")
		tui.commandState = StateComplete
		return
	}

	total := len(domains)
	tui.addOutput(fmt.Sprintf("[*] Rescanning %d domains (%d workers)...", total, maxWorkers))
	tui.addOutput("")

	ctx, cancel := context.WithCancel(context.Background())
	tui.cancelScan = cancel

	go func() {
		defer cancel()
		defer tui.closeLog()

		var aliveCount, dnsOnlyCount, deadCount int64
		var mu sync.Mutex
		var failedDomains []string
		var responseTimes []int64

		// Concurrent rescan
		sem := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup

		for _, domain := range domains {
			select {
			case <-ctx.Done():
				break
			default:
			}

			sem <- struct{}{}
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }()

				select {
				case <-ctx.Done():
					return
				default:
				}

				result := tui.checker.Check(ctx, d)
				tui.db.UpsertSite(result)
				n := atomic.AddInt64(&tui.scanned, 1)

				switch result.Status {
				case "alive":
					atomic.AddInt64(&aliveCount, 1)
					atomic.AddInt64(&tui.alive, 1)
					tui.addOutput(fmt.Sprintf("[+] (%d/%d) %s ALIVE %d %dms", n, total, d, result.HTTPStatus, result.HTTPRespMs))
					mu.Lock()
					responseTimes = append(responseTimes, result.HTTPRespMs)
					mu.Unlock()
				case "dns_only":
					atomic.AddInt64(&dnsOnlyCount, 1)
					atomic.AddInt64(&tui.dnsOnly, 1)
					tui.addOutput(fmt.Sprintf("[!] (%d/%d) %s DNS-ONLY", n, total, d))
				default:
					atomic.AddInt64(&deadCount, 1)
					atomic.AddInt64(&tui.dead, 1)
					tui.addOutput(fmt.Sprintf("[-] (%d/%d) %s DEAD", n, total, d))
					mu.Lock()
					failedDomains = append(failedDomains, d)
					mu.Unlock()
				}
			}(domain)
		}
		wg.Wait()

		select {
		case <-ctx.Done():
			tui.addOutput("[!] Rescan cancelled")
			goto done
		default:
		}

		// Retry pass
		if len(failedDomains) > 0 {
			tui.addOutput(fmt.Sprintf("[*] ── RETRY: %d failed domains (3x timeout) ──", len(failedDomains)))
			retryChecker := NewChecker(tui.checker.timeout * 3)
			var retryRecovered int64

			for _, domain := range failedDomains {
				select {
				case <-ctx.Done():
					goto done
				default:
				}
				sem <- struct{}{}
				wg.Add(1)
				go func(d string) {
					defer wg.Done()
					defer func() { <-sem }()
					result := retryChecker.Check(ctx, d)
					if result.Status == "alive" || result.Status == "dns_only" {
						tui.db.UpsertSite(result)
						atomic.AddInt64(&retryRecovered, 1)
						if result.Status == "alive" {
							atomic.AddInt64(&aliveCount, 1)
							atomic.AddInt64(&deadCount, -1)
							atomic.AddInt64(&tui.alive, 1)
							atomic.AddInt64(&tui.dead, -1)
							mu.Lock()
							responseTimes = append(responseTimes, result.HTTPRespMs)
							mu.Unlock()
							tui.addOutput(fmt.Sprintf("[+] RETRY: %s RECOVERED ALIVE", d))
						} else {
							atomic.AddInt64(&dnsOnlyCount, 1)
							atomic.AddInt64(&deadCount, -1)
							tui.addOutput(fmt.Sprintf("[!] RETRY: %s RECOVERED DNS-ONLY", d))
						}
					}
				}(domain)
			}
			wg.Wait()
		}

	done:
		sort.Slice(responseTimes, func(i, j int) bool { return responseTimes[i] < responseTimes[j] })

		tui.addOutput("")
		tui.addOutput(fmt.Sprintf("[*] Rescan complete: %d alive, %d dns-only, %d dead",
			atomic.LoadInt64(&aliveCount), atomic.LoadInt64(&dnsOnlyCount), atomic.LoadInt64(&deadCount)))

		if len(responseTimes) > 0 {
			tui.addOutput(fmt.Sprintf("[*] Response times -- p50: %dms | p90: %dms | p95: %dms",
				percentile(responseTimes, 0.50), percentile(responseTimes, 0.90), percentile(responseTimes, 0.95)))
		}

		tui.commandState = StateComplete
	}()
}

// ════════════════════════════════════════════════════════════════
// TUI - VIEW RESULTS
// ════════════════════════════════════════════════════════════════

func (tui *TUI) viewSitesByStatus(status, title string) {
	sites := tui.db.GetSitesByStatus(status)
	if len(sites) == 0 {
		tui.addOutput(fmt.Sprintf("[!] No %s sites in database", status))
		return
	}

	var lines []string
	for _, s := range sites {
		lines = append(lines, fmt.Sprintf("%-40s", s.Domain))
		if s.DNSAlive {
			lines = append(lines, fmt.Sprintf("  DNS: %s", s.DNSIPs))
		}
		if s.HTTPAlive {
			scheme := "HTTP"
			if s.HTTPTLS {
				scheme = "HTTPS"
			}
			serverInfo := s.HTTPServer
			if s.HTTPPoweredBy != "" {
				serverInfo += " | " + s.HTTPPoweredBy
			}
			lines = append(lines, fmt.Sprintf("  %s %d -- %dms -- %s", scheme, s.HTTPStatus, s.HTTPRespMs, serverInfo))
			if s.HTTPTitle != "" {
				t := truncateToWidth(s.HTTPTitle, 70, "...")
				lines = append(lines, fmt.Sprintf("  Title: %s", t))
			}
			if s.HTTPRedirect != "" {
				lines = append(lines, fmt.Sprintf("  Redirect: %s", s.HTTPRedirect))
			}
			if s.HTTPRedirectChain != "" {
				lines = append(lines, fmt.Sprintf("  Chain: %s", truncateToWidth(s.HTTPRedirectChain, 80, "...")))
			}
			if s.HTTPTLS && s.HTTPTLSExpiry != "" {
				certLine := fmt.Sprintf("  TLS: %s (CN: %s) expires %s (%dd)",
					s.HTTPTLSIssuer, s.HTTPTLSCN, s.HTTPTLSExpiry, s.HTTPTLSDaysLeft)
				if s.HTTPTLSSelfSigned {
					certLine += " [SELF-SIGNED]"
				}
				if s.HTTPTLSDaysLeft <= 30 {
					certLine += " [EXPIRING]"
				}
				lines = append(lines, certLine)
			}
			// Security headers summary
			var secHeaders []string
			if s.HTTPXFrame != "" {
				secHeaders = append(secHeaders, "XFO")
			}
			if s.HTTPHSTS != "" {
				secHeaders = append(secHeaders, "HSTS")
			}
			if len(secHeaders) > 0 {
				lines = append(lines, fmt.Sprintf("  Security: %s", strings.Join(secHeaders, ", ")))
			}
		}
		lines = append(lines, "")
	}

	tui.viewLines = lines
	tui.viewTitle = fmt.Sprintf(" %s (%d sites) ", title, len(sites))
	tui.viewScroll = 0
	tui.commandState = StateViewResults
}

func (tui *TUI) showDBStats() {
	stats := tui.db.GetStats()
	tui.clearOutput()
	tui.addOutput("[*] ═══ DATABASE STATISTICS ═══")
	tui.addOutput(fmt.Sprintf("[*]  DB File: %s", tui.dbPath))
	tui.addOutput(fmt.Sprintf("[*]  Total Sites:  %d", stats.Total))
	tui.addOutput(fmt.Sprintf("[+]  Alive:        %d", stats.Alive))
	tui.addOutput(fmt.Sprintf("[!]  DNS-Only:     %d", stats.DNSOnly))
	tui.addOutput(fmt.Sprintf("[-]  Dead:         %d", stats.Dead))
	tui.addOutput(fmt.Sprintf("[*]  HTTPS Sites:  %d", stats.HTTPSites))
	if stats.Total > 0 {
		pct := float64(stats.Alive) / float64(stats.Total) * 100
		tui.addOutput(fmt.Sprintf("[*]  Alive %%:      %.1f%%", pct))
	}

	// Extended stats from DB
	var selfSigned, expiringSoon int
	tui.db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE http_tls_self_signed=1").Scan(&selfSigned)
	tui.db.conn.QueryRow("SELECT COUNT(*) FROM sites WHERE http_tls_days_left > 0 AND http_tls_days_left <= 30").Scan(&expiringSoon)

	if selfSigned > 0 || expiringSoon > 0 {
		tui.addOutput("")
		tui.addOutput("[*] ═══ TLS CERTIFICATE ALERTS ═══")
		if selfSigned > 0 {
			tui.addOutput(fmt.Sprintf("[!]  Self-Signed Certs: %d", selfSigned))
		}
		if expiringSoon > 0 {
			tui.addOutput(fmt.Sprintf("[!]  Expiring (<=30d):  %d", expiringSoon))
		}
	}

	// Response time stats
	var avgMs sql.NullFloat64
	tui.db.conn.QueryRow("SELECT AVG(http_response_ms) FROM sites WHERE http_alive=1 AND http_response_ms > 0").Scan(&avgMs)
	if avgMs.Valid {
		tui.addOutput("")
		tui.addOutput("[*] ═══ RESPONSE TIMES ═══")
		tui.addOutput(fmt.Sprintf("[*]  Average: %.0fms", avgMs.Float64))
	}
}

func (tui *TUI) exportResults() {
	ts := time.Now().Format("2006-01-02_150405")
	path := filepath.Join(filepath.Dir(tui.dbPath), fmt.Sprintf("frankenstein_export_%s.csv", ts))
	if err := tui.db.ExportCSV(path); err != nil {
		tui.addOutput(fmt.Sprintf("[-] Export failed: %v", err))
		return
	}
	tui.addOutput(fmt.Sprintf("[+] Exported to: %s", path))
}

// ════════════════════════════════════════════════════════════════
// TUI - INPUT HANDLING
// ════════════════════════════════════════════════════════════════

func (tui *TUI) handleMenuAction(index int) {
	switch index {
	case 0: // Check Single Domain
		tui.commandState = StateInput
		tui.inputMode = InputDomain
		tui.inputPrompt = "Enter domain"
		tui.inputBuffer = ""
		tui.inputCursor = 0

	case 1: // Bulk Scan from targets/
		tui.refreshTargetFiles()
		if len(tui.selectItems) == 0 {
			tui.addOutput("[!] No .txt files found in targets/ folders")
			return
		}
		tui.commandState = StateSelect

	case 2: // Bulk Scan from File Path
		tui.commandState = StateInput
		tui.inputMode = InputFile
		tui.inputPrompt = "Enter file path"
		tui.inputBuffer = ""
		tui.inputCursor = 0

	case 3: // View Alive
		tui.viewSitesByStatus("alive", "ALIVE SITES")

	case 4: // View DNS-Only
		tui.viewSitesByStatus("dns_only", "DNS-ONLY SITES")

	case 5: // View Dead
		tui.viewSitesByStatus("dead", "DEAD SITES")

	case 6: // Export
		tui.exportResults()

	case 7: // DB Stats
		tui.showDBStats()

	case 8: // Rescan
		tui.runRescanAll()

	case 9: // Exit
		tui.running = false
	}
}

func (tui *TUI) handleEvent(ev tcell.Event) {
	switch e := ev.(type) {
	case *tcell.EventResize:
		tui.width, tui.height = e.Size()
		tui.screen.Sync()

	case *tcell.EventKey:
		if tui.showSplash {
			tui.showSplash = false
			return
		}

		switch tui.commandState {
		case StateViewResults:
			tui.handleViewResultsKey(e)
		case StateMenu:
			tui.handleMenuKey(e)
		case StateInput:
			tui.handleInputKey(e)
		case StateSelect:
			tui.handleSelectKey(e)
		case StateRunning:
			if e.Key() == tcell.KeyEscape && tui.cancelScan != nil {
				tui.cancelScan()
			}
			if e.Key() == tcell.KeyPgUp {
				tui.outputScroll -= 10
			}
			if e.Key() == tcell.KeyPgDn {
				tui.outputScroll += 10
				if tui.outputScroll > 0 {
					tui.outputScroll = 0
				}
			}
		case StateComplete:
			tui.commandState = StateMenu
		}
	}
}

func (tui *TUI) handleMenuKey(e *tcell.EventKey) {
	switch e.Key() {
	case tcell.KeyEscape:
		tui.running = false
	case tcell.KeyUp:
		tui.menuIndex--
		if tui.menuIndex < 0 {
			tui.menuIndex = len(menuItems) - 1
		}
	case tcell.KeyDown:
		tui.menuIndex++
		if tui.menuIndex >= len(menuItems) {
			tui.menuIndex = 0
		}
	case tcell.KeyEnter:
		tui.handleMenuAction(tui.menuIndex)
	case tcell.KeyRune:
		ch := e.Rune()
		if ch == 'q' || ch == 'Q' {
			tui.running = false
			return
		}
		// Number key shortcut
		for i, item := range menuItems {
			if string(ch) == item.Key {
				tui.menuIndex = i
				tui.handleMenuAction(i)
				return
			}
		}
	}
}

func (tui *TUI) handleInputKey(e *tcell.EventKey) {
	switch e.Key() {
	case tcell.KeyEscape:
		tui.commandState = StateMenu
		tui.screen.HideCursor()

	case tcell.KeyEnter:
		tui.screen.HideCursor()
		input := strings.TrimSpace(tui.inputBuffer)
		if input == "" {
			return
		}
		switch tui.inputMode {
		case InputDomain:
			tui.runSingleScan(input)
		case InputFile:
			path := sanitizePath(input)
			if _, err := os.Stat(path); err != nil {
				tui.addOutput(fmt.Sprintf("[-] File not found: %s", path))
				tui.commandState = StateMenu
				return
			}
			tui.runBulkScan(path)
		}

	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if tui.inputCursor > 0 {
			tui.inputBuffer = tui.inputBuffer[:tui.inputCursor-1] + tui.inputBuffer[tui.inputCursor:]
			tui.inputCursor--
		}

	case tcell.KeyDelete:
		if tui.inputCursor < len(tui.inputBuffer) {
			tui.inputBuffer = tui.inputBuffer[:tui.inputCursor] + tui.inputBuffer[tui.inputCursor+1:]
		}

	case tcell.KeyLeft:
		if tui.inputCursor > 0 {
			tui.inputCursor--
		}

	case tcell.KeyRight:
		if tui.inputCursor < len(tui.inputBuffer) {
			tui.inputCursor++
		}

	case tcell.KeyHome, tcell.KeyCtrlA:
		tui.inputCursor = 0

	case tcell.KeyEnd, tcell.KeyCtrlE:
		tui.inputCursor = len(tui.inputBuffer)

	case tcell.KeyCtrlV:
		// Paste support --handled by terminal sending chars

	case tcell.KeyRune:
		ch := e.Rune()
		tui.inputBuffer = tui.inputBuffer[:tui.inputCursor] + string(ch) + tui.inputBuffer[tui.inputCursor:]
		tui.inputCursor++
	}
}

func (tui *TUI) handleSelectKey(e *tcell.EventKey) {
	switch e.Key() {
	case tcell.KeyEscape:
		tui.commandState = StateMenu

	case tcell.KeyUp:
		tui.selectIndex--
		if tui.selectIndex < 0 {
			tui.selectIndex = len(tui.selectItems) - 1
		}

	case tcell.KeyDown:
		tui.selectIndex++
		if tui.selectIndex >= len(tui.selectItems) {
			tui.selectIndex = 0
		}

	case tcell.KeyEnter:
		if tui.selectIndex < len(tui.selectPaths) {
			tui.runBulkScan(tui.selectPaths[tui.selectIndex])
		}
	}
}

func (tui *TUI) handleViewResultsKey(e *tcell.EventKey) {
	switch e.Key() {
	case tcell.KeyEscape, tcell.KeyRune:
		if e.Key() == tcell.KeyRune && e.Rune() != 'q' && e.Rune() != 'Q' {
			return
		}
		tui.commandState = StateMenu
	case tcell.KeyUp:
		tui.viewScroll--
		if tui.viewScroll < 0 {
			tui.viewScroll = 0
		}
	case tcell.KeyDown:
		tui.viewScroll++
		maxScroll := len(tui.viewLines) - (tui.height - 5)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if tui.viewScroll > maxScroll {
			tui.viewScroll = maxScroll
		}
	case tcell.KeyPgUp:
		tui.viewScroll -= 20
		if tui.viewScroll < 0 {
			tui.viewScroll = 0
		}
	case tcell.KeyPgDn:
		tui.viewScroll += 20
		maxScroll := len(tui.viewLines) - (tui.height - 5)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if tui.viewScroll > maxScroll {
			tui.viewScroll = maxScroll
		}
	}
}

// ════════════════════════════════════════════════════════════════
// TUI - MAIN LOOP
// ════════════════════════════════════════════════════════════════

func (tui *TUI) Run() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for tui.running {
			ev := tui.screen.PollEvent()
			if ev == nil {
				return
			}
			tui.handleEvent(ev)
		}
	}()

	for tui.running {
		<-ticker.C
		tui.render()
	}
}

// ════════════════════════════════════════════════════════════════
// MAIN --3-STEP DB PATH RESOLUTION
// ════════════════════════════════════════════════════════════════

func main() {
	if os.Getenv("TERM") == "" {
		os.Setenv("TERM", "xterm-256color")
	}

	dbPath := "frankenstein.db"
	timeout := 15 * time.Second

	// Step 1: LINUX/WINDOWS subfolder check
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		dirName := strings.ToUpper(filepath.Base(exeDir))
		if dirName == "LINUX" || dirName == "WINDOWS" {
			dbPath = filepath.Join(filepath.Dir(exeDir), "frankenstein.db")
		}
	}

	// Step 2: Recon-suite fallback
	if !filepath.IsAbs(dbPath) {
		if home, err := os.UserHomeDir(); err == nil {
			reconDir := filepath.Join(home, "Documents", "recon-suite", "Frankenstein")
			if info, err := os.Stat(reconDir); err == nil && info.IsDir() {
				dbPath = filepath.Join(reconDir, "frankenstein.db")
			}
		}
	}

	// Step 3: CWD fallback (make absolute)
	if !filepath.IsAbs(dbPath) {
		if cwd, err := os.Getwd(); err == nil {
			dbPath = filepath.Join(cwd, dbPath)
		}
	}

	// CLI overrides
	for i, arg := range os.Args {
		if arg == "-db" && i+1 < len(os.Args) {
			dbPath = os.Args[i+1]
		}
		if arg == "-t" && i+1 < len(os.Args) {
			if d, err := time.ParseDuration(os.Args[i+1]); err == nil {
				timeout = d
			}
		}
	}

	tui, err := NewTUI(dbPath, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		os.Exit(1)
	}
	defer tui.Close()
	tui.Run()
}
