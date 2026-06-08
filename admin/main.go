package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"bufio"
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
	flagDNS         = flag.String("dns", "172.16.2.1", "DNS server for client configs")
	flagSRMSessions = flag.String("srm-sessions", "/usr/syno/etc/private/session/current.users", "SRM active sessions file (empty=disabled)")
	flagQREncode    = flag.String("qrencode", "/usr/syno/bin/qrencode", "path to qrencode binary")
)

type Peer struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type PeersDB struct {
	Peers []Peer `json:"peers"`
}

type App struct {
	dir          string
	endpoint     string
	iface        string
	dns          string
	wgBin        string
	qrBin        string
	srmSessions  string // path to SRM current.users session file
	passFile     string
	sessionKey   []byte
	mu           sync.Mutex
	tmpl         *template.Template
	loginTmpl    *template.Template
	qrTmpl       *template.Template
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
	mux.HandleFunc("/peers/delete", app.require(app.handleDelete))
	mux.HandleFunc("/", app.require(app.handleIndex))

	log.Printf("Listening on http://%s", *flagAddr)
	log.Fatal(http.ListenAndServe(*flagAddr, mux))
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func (app *App) shadowEnabled() bool {
	// Shadow auth is available whenever /etc/shadow is readable (i.e. running as root).
	// The pass file (setpassword) is an optional additional credential source.
	_, err := os.Stat("/etc/shadow")
	return err == nil
}

// checkAuth tries SRM session file first, then a local signed session cookie.
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

// verifySRM reads the SRM session file and checks whether the request's "id"
// cookie corresponds to an active session. This avoids the IP-binding issue
// that breaks API-based session verification.
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
	// SRM shadow auth for any user, or the app's own pass file as a fallback.
	// Pass file is username-agnostic so it works even if SRM's admin is locked.
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
	http.SetCookie(w, &http.Cookie{
		Name:   "wg_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type indexData struct {
	Peers []peerRow
}

type peerRow struct {
	Peer
	LastHandshake string
	HasKey        bool
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
		rows = append(rows, peerRow{
			Peer:          p,
			LastHandshake: hs[p.PublicKey],
			HasKey:        p.PrivateKey != "",
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	app.tmpl.Execute(w, indexData{Peers: rows})
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
	peer := Peer{Name: name, Address: addr, PrivateKey: privKey, PublicKey: pubKey}
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
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, p.PrivateKey, p.Address, app.dns, app.serverPublicKey(), app.endpoint)
}

func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// ── Templates ─────────────────────────────────────────────────────────────────

const loginHTML = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireGuard Admin</title>
<style>
body{font-family:sans-serif;max-width:360px;margin:80px auto;padding:0 20px;color:#222}
h1{font-size:20px;margin-bottom:24px}
label{display:block;margin-bottom:4px;font-size:14px}
input{width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;margin-bottom:14px;font-size:14px;box-sizing:border-box}
button{width:100%;padding:9px;background:#333;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer}
button:hover{background:#555}
.err{color:#c00;margin-bottom:14px;font-size:14px}
</style>
</head>
<body>
<h1>WireGuard Admin</h1>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="next" value="{{.Next}}">
<label>Username</label>
<input type="text" name="username" autocomplete="username" required autofocus>
<label>Password</label>
<input type="password" name="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
</body>
</html>`

const indexHTML = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireGuard Peers</title>
<style>
*{box-sizing:border-box}
body{font-family:sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#222}
h1{margin-bottom:24px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #e5e5e5}
th{background:#f7f7f7;font-weight:600}
tr:hover td{background:#fafafa}
.btn{display:inline-block;padding:5px 11px;border:1px solid #ccc;border-radius:4px;background:#fff;font-size:13px;text-decoration:none;color:#222;cursor:pointer;line-height:1.4}
.btn:hover{background:#f0f0f0}
.btn-red{border-color:#e88;color:#c00}
.btn-red:hover{background:#fff0f0}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.add{margin-top:24px;display:flex;gap:8px;align-items:center}
.add input{padding:7px 10px;border:1px solid #ccc;border-radius:4px;font-size:14px;width:220px}
.dim{color:#999;font-size:13px}
</style>
</head>
<body>
<h1>WireGuard Peers</h1>
<table>
<thead><tr><th>Name</th><th>VPN IP</th><th>Last Handshake</th><th>Actions</th></tr></thead>
<tbody>
{{range .Peers}}
<tr>
  <td>{{.Name}}</td>
  <td>{{.Address}}</td>
  <td>{{if .LastHandshake}}{{.LastHandshake}}{{else}}<span class="dim">never</span>{{end}}</td>
  <td class="actions">
    {{if .HasKey}}
    <a class="btn" href="/peers/qr?key={{.PublicKey}}">QR Code</a>
    <a class="btn" href="/peers/config?key={{.PublicKey}}" download>Config</a>
    {{else}}
    <span class="dim">no private key (imported)</span>
    {{end}}
    <form style="display:inline" method="post" action="/peers/delete">
      <input type="hidden" name="key" value="{{.PublicKey}}">
      <button class="btn btn-red" onclick="return confirm('Delete {{.Name}}?')">Delete</button>
    </form>
  </td>
</tr>
{{else}}
<tr><td colspan="4" style="text-align:center;color:#999;padding:32px">No peers yet</td></tr>
{{end}}
</tbody>
</table>
<div class="add">
  <form method="post" action="/peers/add">
    <input type="text" name="name" placeholder="e.g. Phone, Laptop" required>
    <button class="btn" type="submit">Add Peer</button>
  </form>
</div>
<p style="margin-top:32px"><a href="/logout" style="color:#999;font-size:13px">Sign out</a></p>
</body>
</html>`

const qrHTML = `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Name}} — WireGuard Config</title>
<style>
*{box-sizing:border-box}
body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 20px;color:#222}
h1{margin-bottom:4px}
.sub{color:#888;margin-bottom:28px;font-size:14px}
.qr{text-align:center;margin:0 0 24px}
.qr img{border:1px solid #e5e5e5;padding:12px;border-radius:8px}
pre{background:#f7f7f7;padding:16px;border-radius:6px;font-size:13px;line-height:1.6;overflow-x:auto;white-space:pre-wrap}
.actions{display:flex;gap:8px;margin-top:20px}
.btn{display:inline-block;padding:7px 14px;border:1px solid #ccc;border-radius:4px;background:#fff;font-size:14px;text-decoration:none;color:#222;cursor:pointer}
.btn:hover{background:#f0f0f0}
</style>
</head>
<body>
<h1>{{.Name}}</h1>
<p class="sub">Scan the QR code or download the config file, then import into your WireGuard app.</p>
<div class="qr">
  <img src="/peers/qr?key={{.PubKey}}&img=1" width="256" height="256" alt="WireGuard QR code">
</div>
<pre>{{.Config}}</pre>
<div class="actions">
  <a class="btn" href="/peers/config?key={{.PubKey}}" download>Download .conf</a>
  <a class="btn" href="/">← Back</a>
</div>
</body>
</html>`
