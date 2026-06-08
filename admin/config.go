package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sha512crypt "github.com/tredoe/osutil/user/crypt/sha512_crypt"
	sha256crypt "github.com/tredoe/osutil/user/crypt/sha256_crypt"
)

// ── Password setup ────────────────────────────────────────────────────────────

func runSetPassword(path string, args []string) {
	var pass string
	if len(args) > 0 {
		pass = args[0]
	} else {
		fmt.Print("Password: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(line)
	}
	if pass == "" {
		log.Fatal("password cannot be empty")
	}
	// Store as a bcrypt-style entry using sha512crypt so it's the same format
	// as /etc/shadow and doesn't require an extra dependency.
	salt, err := randomSalt()
	if err != nil {
		log.Fatal("salt:", err)
	}
	c := sha512crypt.New()
	hash, err := c.Generate([]byte(pass), []byte("$6$"+salt))
	if err != nil {
		log.Fatal("hash:", err)
	}
	if err := os.WriteFile(path, []byte(hash), 0600); err != nil {
		log.Fatal("write:", err)
	}
	fmt.Println("Password set.")
}

func randomSalt() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// ── Shadow / password file verification ──────────────────────────────────────

// verifyShadow checks a username/password against /etc/shadow.
// Falls back to verifying against the app's own password file if username is empty.
func verifyShadow(username, password string) bool {
	hash := shadowHash(username)
	if hash == "" {
		return false
	}
	return verifyCrypt(hash, password)
}

func shadowHash(username string) string {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		log.Printf("cannot read /etc/shadow: %v", err)
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ":", 3)
		if len(fields) >= 2 && fields[0] == username {
			h := fields[1]
			if h == "" || h == "!" || h == "*" || h == "x" {
				return ""
			}
			return h
		}
	}
	return ""
}

func verifyCrypt(hash, password string) bool {
	var generated string
	var err error
	switch {
	case strings.HasPrefix(hash, "$6$"):
		generated, err = sha512crypt.New().Generate([]byte(password), []byte(hash))
	case strings.HasPrefix(hash, "$5$"):
		generated, err = sha256crypt.New().Generate([]byte(password), []byte(hash))
	default:
		log.Printf("unsupported hash algorithm: %.3s", hash)
		return false
	}
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(generated), []byte(hash)) == 1
}

// verifyPassFile checks a password against the app's own password file,
// used when shadow auth is configured via 'wg-admin setpassword'.
func (app *App) verifyPassFile(password string) bool {
	hash, err := os.ReadFile(app.passFile)
	if err != nil {
		return false
	}
	return verifyCrypt(strings.TrimSpace(string(hash)), password)
}

// ── Key generation ────────────────────────────────────────────────────────────

func generateKeyPair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		nil
}

func derivePublicKey(privB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(raw) != 32 {
		return ""
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// ── Peers persistence ─────────────────────────────────────────────────────────

func (app *App) peersFile() string { return filepath.Join(app.dir, "peers.json") }
func (app *App) wgConfFile() string { return filepath.Join(app.dir, "wg0.conf") }

func (app *App) loadPeers() (*PeersDB, error) {
	data, err := os.ReadFile(app.peersFile())
	if os.IsNotExist(err) {
		return &PeersDB{}, nil
	}
	if err != nil {
		return nil, err
	}
	var db PeersDB
	return &db, json.Unmarshal(data, &db)
}

func (app *App) savePeers(db *PeersDB) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(app.peersFile(), data, 0600)
}

// importExistingPeers adds any peers found in wg0.conf but not in peers.json.
// Imported peers have no private key and cannot display a QR code.
func (app *App) importExistingPeers() {
	db, err := app.loadPeers()
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, p := range db.Peers {
		known[p.PublicKey] = true
	}
	var added bool
	for _, wp := range app.loadWGConfPeers() {
		if known[wp.PublicKey] {
			continue
		}
		addr := wp.AllowedIPs
		if idx := strings.Index(addr, "/"); idx != -1 {
			addr = addr[:idx]
		}
		name := wp.Comment
		if name == "" {
			name = "imported peer"
		}
		db.Peers = append(db.Peers, Peer{
			Name:      name,
			Address:   addr,
			PublicKey: wp.PublicKey,
		})
		added = true
	}
	if added {
		_ = app.savePeers(db)
	}
}

type wgConfPeer struct {
	Comment    string
	PublicKey  string
	AllowedIPs string
}

func (app *App) loadWGConfPeers() []wgConfPeer {
	data, err := os.ReadFile(app.wgConfFile())
	if err != nil {
		return nil
	}
	var peers []wgConfPeer
	var cur *wgConfPeer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[Peer]" {
			if cur != nil {
				peers = append(peers, *cur)
			}
			cur = &wgConfPeer{}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "#") && cur.Comment == "":
			cur.Comment = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		case strings.HasPrefix(line, "PublicKey"):
			cur.PublicKey = fieldValue(line)
		case strings.HasPrefix(line, "AllowedIPs"):
			cur.AllowedIPs = fieldValue(line)
		}
	}
	if cur != nil {
		peers = append(peers, *cur)
	}
	return peers
}

// writeWGConf rewrites wg0.conf keeping the [Interface] section intact and
// regenerating all [Peer] sections from db.
func (app *App) writeWGConf(db *PeersDB) error {
	existing, err := os.ReadFile(app.wgConfFile())
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString(ifaceSection(existing))
	for _, p := range db.Peers {
		fmt.Fprintf(&buf, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n",
			p.Name, p.PublicKey, p.Address)
	}
	return os.WriteFile(app.wgConfFile(), buf.Bytes(), 0600)
}

// ifaceSection returns everything up to (not including) the first [Peer] line.
func ifaceSection(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var buf bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "[Peer]" {
			break
		}
		buf.WriteString(line + "\n")
	}
	return strings.TrimRight(buf.String(), "\n") + "\n"
}

// nextAddress finds the lowest available /32 in the VPN subnet.
func (app *App) nextAddress(db *PeersDB) (string, error) {
	data, err := os.ReadFile(app.wgConfFile())
	if err != nil {
		return "", err
	}
	var cidr string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// matches both "#Address = ..." and "# Address = ..."
		if strings.HasPrefix(line, "#") && strings.Contains(line, "Address") && strings.Contains(line, "=") {
			cidr = strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			break
		}
	}
	if cidr == "" {
		return "", fmt.Errorf("no #Address line found in wg0.conf")
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	base := []byte(ipNet.IP.To4())

	used := map[string]bool{}
	routerIP := make(net.IP, 4)
	copy(routerIP, base)
	routerIP[3] = 1
	used[routerIP.String()] = true
	for _, p := range db.Peers {
		used[p.Address] = true
	}

	for i := 2; i < 254; i++ {
		candidate := make(net.IP, 4)
		copy(candidate, base)
		candidate[3] = byte(i)
		if !used[candidate.String()] && ipNet.Contains(candidate) {
			return candidate.String(), nil
		}
	}
	return "", fmt.Errorf("no free addresses in %s", cidr)
}

// ── WireGuard operations ──────────────────────────────────────────────────────

func (app *App) serverPublicKey() string {
	data, err := os.ReadFile(app.wgConfFile())
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "PrivateKey") {
			return derivePublicKey(fieldValue(line))
		}
	}
	return ""
}

func (app *App) applyPeerAdd(p Peer) {
	out, err := exec.Command(app.wgBin, "set", app.iface,
		"peer", p.PublicKey, "allowed-ips", p.Address+"/32").CombinedOutput()
	if err != nil {
		log.Printf("wg set peer add: %v: %s", err, out)
	}
}

func (app *App) applyPeerRemove(pubKey string) {
	out, err := exec.Command(app.wgBin, "set", app.iface, "peer", pubKey, "remove").CombinedOutput()
	if err != nil {
		log.Printf("wg set peer remove: %v: %s", err, out)
	}
}

func (app *App) getHandshakes() map[string]string {
	out, err := exec.Command(app.wgBin, "show", app.iface, "dump").Output()
	if err != nil {
		return nil
	}
	result := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip interface line
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		pubKey, tsStr := fields[0], fields[4]
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil || ts == 0 {
			result[pubKey] = "never"
			continue
		}
		ago := time.Since(time.Unix(ts, 0)).Round(time.Second)
		result[pubKey] = ago.String() + " ago"
	}
	return result
}

func (app *App) generateQR(content string) ([]byte, error) {
	cmd := exec.Command(app.qrBin, "-o", "-", "-t", "PNG")
	cmd.Stdin = strings.NewReader(content)
	return cmd.Output()
}

func fieldValue(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
