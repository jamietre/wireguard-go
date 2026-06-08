package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	flagDir         = flag.String("dir", "/volume1/wireguard", "wireguard config directory")
	flagAddr        = flag.String("addr", "0.0.0.0:8080", "listen address")
	flagEndpoint    = flag.String("endpoint", "", "public endpoint for client configs (host:port)")
	flagIface       = flag.String("iface", "wg0", "wireguard interface")
	flagDNS         = flag.String("dns", "", "default DNS for client configs")
	flagSRMSessions = flag.String("srm-sessions", "/usr/syno/etc/private/session/current.users", "SRM active sessions file (empty=disabled)")
	flagQREncode    = flag.String("qrencode", "/usr/syno/bin/qrencode", "path to qrencode binary")
)

type Peer struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips,omitempty"` // client-side; empty = 0.0.0.0/0, ::/0
	DNS        string `json:"dns,omitempty"`          // client-side; empty = server default
}

type PeersDB struct {
	Peers []Peer `json:"peers"`
}

type App struct {
	dir         string
	endpoint    string
	iface       string
	dns         string
	wgBin       string
	qrBin       string
	srmSessions string
	passFile    string
	sessionKey  []byte
	mu          sync.Mutex
	tmpl        *template.Template
	loginTmpl   *template.Template
	qrTmpl      *template.Template
}

func main() {
	flag.Parse()

	if len(flag.Args()) > 0 && flag.Args()[0] == "setpassword" {
		runSetPassword(filepath.Join(*flagDir, ".admin_password"), flag.Args()[1:])
		return
	}

	app := &App{
		dir:         *flagDir,
		endpoint:    *flagEndpoint,
		iface:       *flagIface,
		dns:         *flagDNS,
		wgBin:       filepath.Join(*flagDir, "bin", "wg"),
		qrBin:       *flagQREncode,
		srmSessions: *flagSRMSessions,
		passFile:    filepath.Join(*flagDir, ".admin_password"),
	}

	app.sessionKey = make([]byte, 32)
	if _, err := rand.Read(app.sessionKey); err != nil {
		log.Fatal("session key:", err)
	}

	app.tmpl = template.Must(template.New("index").Parse(indexHTML))
	app.loginTmpl = template.Must(template.New("login").Parse(loginHTML))
	app.qrTmpl = template.Must(template.New("qr").Parse(qrHTML))

	app.mu.Lock()
	app.importExistingPeers()
	app.mu.Unlock()

	if app.srmSessions == "" && !app.shadowEnabled() {
		log.Fatal("no auth configured: ensure /etc/shadow is readable or run 'wg-admin setpassword'")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/peers/qr", app.require(app.handleQR))
	mux.HandleFunc("/peers/config", app.require(app.handleConfigDownload))
	mux.HandleFunc("/peers/add", app.require(app.handleAdd))
	mux.HandleFunc("/peers/edit", app.require(app.handleEdit))
	mux.HandleFunc("/peers/delete", app.require(app.handleDelete))
	mux.HandleFunc("/", app.require(app.handleIndex))

	log.Printf("Listening on http://%s", *flagAddr)
	log.Fatal(http.ListenAndServe(*flagAddr, mux))
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func (app *App) shadowEnabled() bool {
	_, err := os.Stat("/etc/shadow")
	return err == nil
}

func (app *App) checkAuth(r *http.Request) bool {
	if app.srmSessions != "" && app.verifySRM(r) {
		return true
	}
	c, err := r.Cookie("wg_session")
	if err != nil {
		return false
	}
	_, ok := app.verifySession(c.Value)
	return ok
}

func (app *App) verifySRM(r *http.Request) bool {
	cookie, err := r.Cookie("id")
	if err != nil || cookie.Value == "" {
		return false
	}
	f, err := os.Open(app.srmSessions)
	if err != nil {
		return false
	}
	defer f.Close()

	var entry struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.ID == cookie.Value && entry.Name != "" {
			return true
		}
	}
	return false
}

func (app *App) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if app.checkAuth(r) {
			next(w, r)
			return
		}
		if app.shadowEnabled() {
			http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// ── Session tokens ────────────────────────────────────────────────────────────

const sessionDuration = 24 * time.Hour

func (app *App) makeSession(username string) string {
	exp := strconv.FormatInt(time.Now().Add(sessionDuration).Unix(), 10)
	payload := base64.RawURLEncoding.EncodeToString([]byte(username + "|" + exp))
	mac := hmac.New(sha256.New, app.sessionKey)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func (app *App) verifySession(token string) (string, bool) {
	dot := strings.LastIndex(token, ".")
	if dot < 0 {
		return "", false
	}
	payload, sig := token[:dot], token[dot+1:]
	mac := hmac.New(sha256.New, app.sessionKey)
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return parts[0], true
}

// ── Handlers ──────────────────────────────────────────────────────────────────

type loginData struct {
	Error string
	Next  string
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !app.shadowEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if app.checkAuth(r) {
			http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		app.loginTmpl.Execute(w, loginData{Next: r.URL.Query().Get("next")})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	next := safeNext(r.FormValue("next"))
	if !verifyShadow(user, pass) && !app.verifyPassFile(pass) {
		app.loginTmpl.Execute(w, loginData{Error: "Invalid username or password.", Next: next})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "wg_session",
		Value:    app.makeSession(user),
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "wg_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type peerRow struct {
	Peer
	LastHandshake string
	Status        string // "connected" | "idle" | "never"
	HasKey        bool
	Custom        bool // non-default AllowedIPs or DNS
}

type indexData struct {
	Peers      []peerRow
	DefaultDNS string
}

func peerStatus(hs string) string {
	if hs == "" || hs == "never" {
		return "never"
	}
	d, err := time.ParseDuration(strings.TrimSuffix(hs, " ago"))
	if err != nil {
		return "idle"
	}
	if d < 3*time.Minute {
		return "connected"
	}
	return "idle"
}

func (app *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	app.mu.Lock()
	db, err := app.loadPeers()
	app.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hs := app.getHandshakes()
	var rows []peerRow
	for _, p := range db.Peers {
		ago := hs[p.PublicKey]
		rows = append(rows, peerRow{
			Peer:          p,
			LastHandshake: ago,
			Status:        peerStatus(ago),
			HasKey:        p.PrivateKey != "",
			Custom:        p.AllowedIPs != "" || p.DNS != "",
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	app.tmpl.Execute(w, indexData{Peers: rows, DefaultDNS: app.dns})
}

func (app *App) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	allowedIPs := strings.TrimSpace(r.FormValue("allowed_ips"))
	dns := strings.TrimSpace(r.FormValue("dns"))

	app.mu.Lock()
	defer app.mu.Unlock()

	privKey, pubKey, err := generateKeyPair()
	if err != nil {
		http.Error(w, "key error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	db, err := app.loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	addr, err := app.nextAddress(db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	peer := Peer{
		Name:       name,
		Address:    addr,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		AllowedIPs: allowedIPs,
		DNS:        dns,
	}
	db.Peers = append(db.Peers, peer)
	if err := app.savePeers(db); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := app.writeWGConf(db); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app.applyPeerAdd(peer)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) handleEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pubKey := r.FormValue("key")
	allowedIPs := strings.TrimSpace(r.FormValue("allowed_ips"))
	dns := strings.TrimSpace(r.FormValue("dns"))

	app.mu.Lock()
	defer app.mu.Unlock()

	db, err := app.loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var found bool
	for i, p := range db.Peers {
		if p.PublicKey == pubKey {
			db.Peers[i].AllowedIPs = allowedIPs
			db.Peers[i].DNS = dns
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	if err := app.savePeers(db); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pubKey := r.FormValue("key")
	app.mu.Lock()
	defer app.mu.Unlock()

	db, err := app.loadPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var found bool
	var kept []Peer
	for _, p := range db.Peers {
		if p.PublicKey == pubKey {
			found = true
		} else {
			kept = append(kept, p)
		}
	}
	if !found {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}
	db.Peers = kept
	if err := app.savePeers(db); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := app.writeWGConf(db); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app.applyPeerRemove(pubKey)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type qrData struct {
	Name   string
	PubKey string
	Config string
}

func (app *App) handleQR(w http.ResponseWriter, r *http.Request) {
	pubKey := r.URL.Query().Get("key")
	peer := app.findPeer(pubKey)
	if peer == nil || peer.PrivateKey == "" {
		http.Error(w, "peer not found or no private key", http.StatusNotFound)
		return
	}
	conf := app.clientConfig(peer)
	if r.URL.Query().Get("img") == "1" {
		png, err := app.generateQR(conf)
		if err != nil {
			http.Error(w, "qrencode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	app.qrTmpl.Execute(w, qrData{Name: peer.Name, PubKey: pubKey, Config: conf})
}

func (app *App) handleConfigDownload(w http.ResponseWriter, r *http.Request) {
	pubKey := r.URL.Query().Get("key")
	peer := app.findPeer(pubKey)
	if peer == nil || peer.PrivateKey == "" {
		http.Error(w, "peer not found or no private key", http.StatusNotFound)
		return
	}
	safe := strings.NewReplacer(" ", "_", "/", "_", "\\", "_").Replace(peer.Name)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safe+`.conf"`)
	fmt.Fprint(w, app.clientConfig(peer))
}

func (app *App) findPeer(pubKey string) *Peer {
	app.mu.Lock()
	defer app.mu.Unlock()
	db, err := app.loadPeers()
	if err != nil {
		return nil
	}
	for _, p := range db.Peers {
		if p.PublicKey == pubKey {
			cp := p
			return &cp
		}
	}
	return nil
}

func (app *App) clientConfig(p *Peer) string {
	allowedIPs := p.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}
	dns := p.DNS
	if dns == "" {
		dns = app.dns
	}
	var buf strings.Builder
	buf.WriteString("[Interface]\n")
	fmt.Fprintf(&buf, "PrivateKey = %s\n", p.PrivateKey)
	fmt.Fprintf(&buf, "Address = %s/32\n", p.Address)
	if dns != "" {
		fmt.Fprintf(&buf, "DNS = %s\n", dns)
	}
	buf.WriteString("\n[Peer]\n")
	fmt.Fprintf(&buf, "PublicKey = %s\n", app.serverPublicKey())
	fmt.Fprintf(&buf, "Endpoint = %s\n", app.endpoint)
	fmt.Fprintf(&buf, "AllowedIPs = %s\n", allowedIPs)
	buf.WriteString("PersistentKeepalive = 25\n")
	return buf.String()
}

func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// ── Templates ─────────────────────────────────────────────────────────────────

const sharedCSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#06090e;
  --card:#0c1420;
  --border:#162030;
  --text:#8fafc4;
  --bright:#c2d8e8;
  --dim:#364f62;
  --accent:#22d3ee;
  --green:#4ade80;
  --yellow:#fbbf24;
  --red:#f87171;
  --mono:'IBM Plex Mono',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;line-height:1.5;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
input{background:var(--bg);border:1px solid var(--border);border-radius:3px;color:var(--bright);font-family:var(--mono);font-size:12px;padding:7px 10px;outline:none;transition:border-color .15s;width:100%}
input:focus{border-color:var(--accent)}
input::placeholder{color:var(--dim)}
.btn{display:inline-flex;align-items:center;padding:5px 10px;border:1px solid var(--border);border-radius:3px;background:transparent;color:var(--text);font-family:var(--mono);font-size:11px;cursor:pointer;transition:border-color .15s,color .15s,background .15s;white-space:nowrap;text-decoration:none;letter-spacing:.02em}
.btn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
.btn-accent{border-color:var(--accent);color:var(--accent)}
.btn-accent:hover{background:rgba(34,211,238,.08)}
.btn-danger{color:var(--red)}
.btn-danger:hover{border-color:var(--red);background:rgba(248,113,113,.06);color:var(--red)}
`

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wg-admin</title>
<style>
` + sharedCSS + `
body{display:flex;flex-direction:column;align-items:center;justify-content:center}
.card{width:320px;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:32px}
.logo{color:var(--accent);font-size:15px;font-weight:500;letter-spacing:.08em;margin-bottom:6px}
.logo-sub{color:var(--dim);font-size:11px;margin-bottom:28px}
.err{color:var(--red);font-size:11px;margin-bottom:16px;padding:8px 10px;border:1px solid rgba(248,113,113,.3);border-radius:3px;background:rgba(248,113,113,.05)}
.field{margin-bottom:16px}
.field label{display:block;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);margin-bottom:6px}
.submit{width:100%;margin-top:4px;padding:8px;border:1px solid var(--accent);border-radius:3px;background:rgba(34,211,238,.08);color:var(--accent);font-family:var(--mono);font-size:12px;cursor:pointer;letter-spacing:.05em;transition:background .15s}
.submit:hover{background:rgba(34,211,238,.15)}
</style>
</head>
<body>
<div class="card">
  <div class="logo">▣ wg-admin</div>
  <div class="logo-sub">WireGuard peer management</div>
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <form method="post" action="/login">
    <input type="hidden" name="next" value="{{.Next}}">
    <div class="field">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" required autofocus>
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required>
    </div>
    <button class="submit" type="submit">sign in →</button>
  </form>
</div>
</body>
</html>`

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wg-admin</title>
<style>
` + sharedCSS + `
header{background:var(--card);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10}
.hdr{max-width:960px;margin:0 auto;padding:0 24px;height:50px;display:flex;align-items:center;gap:16px}
.hdr-logo{color:var(--accent);font-size:14px;font-weight:500;letter-spacing:.06em}
.hdr-iface{color:var(--dim);font-size:11px;padding:2px 7px;border:1px solid var(--border);border-radius:2px}
.hdr-gap{flex:1}
.hdr-out{color:var(--dim);font-size:11px}
.hdr-out:hover{color:var(--text)}
main{max-width:960px;margin:0 auto;padding:36px 24px}
.section-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.section-label{font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--dim)}
table{width:100%;border-collapse:collapse}
thead th{text-align:left;padding:0 12px 10px;font-size:10px;font-weight:400;color:var(--dim);letter-spacing:.1em;text-transform:uppercase;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:hover{background:rgba(12,20,32,.8)}
td{padding:13px 12px;vertical-align:middle}
td.td-name{color:var(--bright);font-weight:500;font-size:13px}
td.td-addr{color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums}
td.td-hs{color:var(--dim);font-size:11px;white-space:nowrap}
td.td-act{white-space:nowrap}
.act-row{display:flex;gap:5px;align-items:center}
.status{display:inline-flex;align-items:center;gap:7px}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot-on{background:var(--green);box-shadow:0 0 5px var(--green);animation:glow 2s ease-in-out infinite}
.dot-idle{background:var(--yellow)}
.dot-off{background:var(--dim)}
@keyframes glow{0%,100%{opacity:1;box-shadow:0 0 5px var(--green)}50%{opacity:.5;box-shadow:0 0 2px var(--green)}}
.badge{font-size:10px;color:var(--dim);border:1px solid var(--border);border-radius:2px;padding:1px 5px;letter-spacing:.04em}
.empty-cell{text-align:center;padding:48px 12px;color:var(--dim);font-size:12px}
.add-wrap{margin-top:28px;border:1px solid var(--border);border-radius:4px}
details summary{padding:12px 16px;cursor:pointer;color:var(--dim);font-size:11px;list-style:none;display:flex;align-items:center;gap:8px;user-select:none;transition:color .15s}
details summary::-webkit-details-marker{display:none}
details summary::before{content:'›';font-size:14px;transition:transform .2s;display:inline-block}
details[open] summary::before{transform:rotate(90deg)}
details[open] summary{color:var(--text);border-bottom:1px solid var(--border)}
.add-form{padding:18px 16px;display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end}
.add-name{display:flex;flex-direction:column;gap:6px}
.add-name label{font-size:10px;color:var(--dim);letter-spacing:.08em;text-transform:uppercase}
.add-advanced{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px}
.field-stack{display:flex;flex-direction:column;gap:6px}
.field-stack label{font-size:10px;color:var(--dim);letter-spacing:.08em;text-transform:uppercase}
.field-hint{font-size:10px;color:var(--dim);margin-top:3px}
dialog{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:0;width:440px;max-width:calc(100vw - 40px);color:var(--text);font-family:var(--mono)}
dialog::backdrop{background:rgba(0,0,0,.75);backdrop-filter:blur(2px)}
.dlg-head{padding:20px 24px 16px;border-bottom:1px solid var(--border)}
.dlg-title{color:var(--bright);font-size:13px;font-weight:500}
.dlg-sub{color:var(--dim);font-size:11px;margin-top:4px}
.dlg-body{padding:20px 24px}
.dlg-field{margin-bottom:14px}
.dlg-field label{display:block;font-size:10px;color:var(--dim);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px}
.dlg-hint{font-size:10px;color:var(--dim);margin-top:4px}
.dlg-foot{padding:16px 24px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end}
</style>
</head>
<body>
<header>
  <div class="hdr">
    <span class="hdr-logo">▣ wg-admin</span>
    <span class="hdr-iface">wg0</span>
    <span class="hdr-gap"></span>
    <a class="hdr-out" href="/logout">sign out</a>
  </div>
</header>
<main>
  <div class="section-hdr">
    <span class="section-label">peers</span>
  </div>
  <table>
    <thead>
      <tr>
        <th>name</th>
        <th>address</th>
        <th>last handshake</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
    {{range .Peers}}
    <tr>
      <td class="td-name">
        <span class="status">
          {{if eq .Status "connected"}}<span class="dot dot-on"></span>
          {{else if eq .Status "idle"}}<span class="dot dot-idle"></span>
          {{else}}<span class="dot dot-off"></span>{{end}}
          {{.Name}}
        </span>
        {{if .Custom}}<span class="badge">custom</span>{{end}}
      </td>
      <td class="td-addr">{{.Address}}</td>
      <td class="td-hs">{{if .LastHandshake}}{{.LastHandshake}}{{else}}—{{end}}</td>
      <td class="td-act">
        <div class="act-row">
        {{if .HasKey}}
          <a class="btn" href="/peers/qr?key={{.PublicKey}}">qr</a>
          <a class="btn" href="/peers/config?key={{.PublicKey}}" download>↓ conf</a>
          <button class="btn" onclick="document.getElementById('edit-{{.PublicKey}}').showModal()">edit</button>
        {{else}}
          <span style="color:var(--dim);font-size:11px">imported</span>
        {{end}}
          <form style="display:inline" method="post" action="/peers/delete">
            <input type="hidden" name="key" value="{{.PublicKey}}">
            <button class="btn btn-danger" onclick="return confirm('Delete {{.Name}}?')">del</button>
          </form>
        </div>
      </td>
    </tr>
    {{else}}
    <tr><td colspan="4" class="empty-cell">no peers configured — add one below</td></tr>
    {{end}}
    </tbody>
  </table>

  <div class="add-wrap">
    <details>
      <summary>add peer</summary>
      <form class="add-form" method="post" action="/peers/add">
        <div class="add-name">
          <label>name</label>
          <input type="text" name="name" placeholder="Phone, Laptop, …" required>
        </div>
        <button class="btn btn-accent" type="submit">create →</button>
        <div class="add-advanced">
          <div class="field-stack">
            <label>AllowedIPs <span style="opacity:.5">(optional)</span></label>
            <input type="text" name="allowed_ips" placeholder="0.0.0.0/0, ::/0">
            <span class="field-hint">leave blank for full tunnel</span>
          </div>
          <div class="field-stack">
            <label>DNS <span style="opacity:.5">(optional)</span></label>
            <input type="text" name="dns" placeholder="{{if .DefaultDNS}}{{.DefaultDNS}}{{else}}none{{end}}">
            <span class="field-hint">leave blank to use server default</span>
          </div>
        </div>
      </form>
    </details>
  </div>
</main>

{{range .Peers}}
{{if .HasKey}}
<dialog id="edit-{{.PublicKey}}">
  <div class="dlg-head">
    <div class="dlg-title">{{.Name}}</div>
    <div class="dlg-sub">{{.Address}} · edit client config</div>
  </div>
  <form method="post" action="/peers/edit">
    <input type="hidden" name="key" value="{{.PublicKey}}">
    <div class="dlg-body">
      <div class="dlg-field">
        <label>AllowedIPs</label>
        <input type="text" name="allowed_ips" value="{{.AllowedIPs}}" placeholder="0.0.0.0/0, ::/0">
        <div class="dlg-hint">comma-separated CIDRs — leave blank for full tunnel</div>
      </div>
      <div class="dlg-field">
        <label>DNS</label>
        <input type="text" name="dns" value="{{.DNS}}" placeholder="{{if $.DefaultDNS}}{{$.DefaultDNS}} (server default){{else}}none{{end}}">
        <div class="dlg-hint">leave blank to use server default</div>
      </div>
    </div>
    <div class="dlg-foot">
      <button type="button" class="btn" onclick="this.closest('dialog').close()">cancel</button>
      <button type="submit" class="btn btn-accent">save changes</button>
    </div>
  </form>
</dialog>
{{end}}
{{end}}

</body>
</html>`

const qrHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Name}} — wg-admin</title>
<style>
` + sharedCSS + `
header{background:var(--card);border-bottom:1px solid var(--border)}
.hdr{max-width:720px;margin:0 auto;padding:0 24px;height:50px;display:flex;align-items:center;gap:16px}
.hdr-logo{color:var(--accent);font-size:14px;font-weight:500;letter-spacing:.06em}
.hdr-gap{flex:1}
.hdr-back{color:var(--dim);font-size:11px}
.hdr-back:hover{color:var(--text)}
main{max-width:720px;margin:0 auto;padding:36px 24px}
.peer-title{color:var(--bright);font-size:18px;font-weight:500;margin-bottom:6px}
.peer-sub{color:var(--dim);font-size:12px;margin-bottom:32px}
.qr-wrap{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:24px;display:inline-block;margin-bottom:28px}
.qr-wrap img{display:block}
.config-label{font-size:10px;color:var(--dim);letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}
pre{background:var(--card);border:1px solid var(--border);border-radius:4px;padding:16px;font-size:12px;line-height:1.7;overflow-x:auto;white-space:pre-wrap;color:var(--text)}
.actions{display:flex;gap:8px;margin-top:20px}
</style>
</head>
<body>
<header>
  <div class="hdr">
    <span class="hdr-logo">▣ wg-admin</span>
    <span class="hdr-gap"></span>
    <a class="hdr-back" href="/">← back</a>
  </div>
</header>
<main>
  <div class="peer-title">{{.Name}}</div>
  <div class="peer-sub">Scan the QR code or download the .conf file, then import into your WireGuard app.</div>
  <div class="qr-wrap">
    <img src="/peers/qr?key={{.PubKey}}&img=1" width="220" height="220" alt="WireGuard QR code">
  </div>
  <div class="config-label">config</div>
  <pre>{{.Config}}</pre>
  <div class="actions">
    <a class="btn btn-accent" href="/peers/config?key={{.PubKey}}" download>↓ download .conf</a>
    <a class="btn" href="/">done</a>
  </div>
</main>
</body>
</html>`
