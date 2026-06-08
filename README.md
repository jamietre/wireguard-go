# wireguard-go for Synology SRM

A fork of [wireguard-go](https://git.zx2c4.com/wireguard-go) that runs on Synology routers
(RT6600AX, RT2600AC) — Linux kernel 4.4.x, aarch64/MT7986A.

Includes a lightweight web-based **peer management UI** (`wg-admin`) for creating and
managing WireGuard clients directly from a browser.

## What's different from upstream

### Kernel 4.4.x epoll fix

**Problem**: Go's epoll implementation uses `EPOLLET` (edge-triggered). On kernel 4.4.60,
`epoll_wait` never fires `EPOLLIN` for UDP sockets, so wireguard-go receives no packets.

**Fix** (`conn/legacyrecv_linux.go`): replaces `makeReceiveIPv4/IPv6` with a
`SetReadDeadline`-based poll loop. Go's timer bypasses epoll — after a 10 ms deadline the
goroutine wakes unconditionally and drains any waiting packets with a non-blocking read.
Maximum added latency is 10 ms per packet. The legacy path is selected automatically at
startup (`conn/batchread_linux.go`) when the running kernel is < 5.0.

### Peer management web UI (`wg-admin`)

A single-binary Go web server in `admin/`. Features:

- Create peers: generates key pair, assigns the next free IP, produces a client config and
  QR code
- View all peers with connection status (last handshake from `wg show`)
- Download config files or display QR code for mobile setup
- **Authentication**: if you are already logged in to SRM, you are admitted automatically
  (reads the SRM session file directly — no API proxy needed). Falls back to a login form
  backed by `/etc/shadow` if an SRM session is not present.

## Installation (pre-built binaries)

Download the latest release archive from the
[Releases page](https://github.com/jamietre/wireguard-go/releases):

```sh
# On your local machine — copy to the router
scp synology-wg-linux-arm64.tar.gz jamiet@172.16.2.1:/tmp/

# On the router
ssh jamiet@172.16.2.1
sudo mkdir -p /volume1/wireguard/bin
cd /tmp && tar xzf synology-wg-linux-arm64.tar.gz -C /volume1/wireguard/bin/
sudo chmod +x /volume1/wireguard/bin/*
```

Then follow the [Configuration](#configuration) and [Init scripts](#init-scripts) steps below.

## Building from source

### Prerequisites

- Go 1.21+
- `aarch64-linux-gnu-gcc` (for cross-compiling `wg`)
- Git (for submodules)

```sh
git clone --recurse-submodules https://github.com/jamietre/wireguard-go.git
cd wireguard-go
make
```

Produces `bin/wireguard-go`, `bin/wg`, and `bin/wg-admin` (all linux/arm64).

### Deploy to router

```sh
./deploy.sh [router-ip] [router-user]
# default: ./deploy.sh 172.16.2.1 jamiet
```

Copies binaries and init scripts to `/volume1/wireguard/` and installs them into
`/usr/local/etc/rc.d/`.

## Configuration

Copy the example config and fill in real keys:

```sh
sudo cp /volume1/wireguard/  # after deploy.sh runs
```

Or on first deploy, `deploy.sh` will tell you there is no config and prompt you to create one.

The example is at `config/wg0.conf.example`. Key fields:

```ini
[Interface]
# Address = 10.10.0.1/24      ← parsed by the init script; not a standard wg field
ListenPort = 51822
PrivateKey = <server private key>

PostUp = iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
```

Generate a key pair:

```sh
wg genkey | tee private.key | wg pubkey
```

## Init scripts

Two init scripts are provided in `rc.d/` and installed to `/usr/local/etc/rc.d/` by
`deploy.sh`.

### `wireguard.sh` — VPN daemon

```sh
sudo /usr/local/etc/rc.d/wireguard.sh start
sudo /usr/local/etc/rc.d/wireguard.sh stop
sudo /usr/local/etc/rc.d/wireguard.sh status
```

Handles `WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1` (required because SRM 4.4.60
advertises native WireGuard but the module is not loaded), loads the `tun` kernel module,
and adds the `MASQUERADE` and firewall rules idempotently.

### `wireguard-admin.sh` — peer management UI

Edit the variables at the top of `rc.d/wireguard-admin.sh` before deploying:

```sh
ENDPOINT="<your-WAN-IP-or-hostname>:51822"   # shown in generated client configs
ADDR="0.0.0.0:8080"                          # bind address for the web UI
DNS="172.16.2.1"                             # DNS shown in client configs
```

```sh
sudo /usr/local/etc/rc.d/wireguard-admin.sh start
# UI available at http://172.16.2.1:8080
```

## SRM notes

- SRM kernel 4.4.60 reports native WireGuard support in `/sys/module/wireguard`, but the
  module is not loaded. `WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1` bypasses this check.
- The `tun` kernel module may need manual loading: `insmod /lib/modules/tun.ko`
- SRM does not NAT custom subnets — the init script adds a `MASQUERADE` rule for the VPN
  subnet.
- SRM's `INPUT_FIREWALL` chain controls inbound access; the init script adds a rule for the
  listen port. This can also be set via **Control Panel → Security → Firewall** for
  persistence across SRM updates.
- The SRM `admin` user is locked for web login; authenticate as any SRM user with a valid
  session, or use the shadow-backed login form.

## Authentication

`wg-admin` checks authentication in this order:

1. **SRM session** — reads `/usr/syno/etc/private/session/current.users` and matches the
   `id` cookie. If you are logged in to SRM, you are admitted without a separate login.
2. **Shadow login form** — if no SRM session is found, a login form is shown. Credentials
   are verified against `/etc/shadow` (the router's local user database). No setup needed
   as long as `wg-admin` runs as root.
3. **Password file fallback** — if needed, set a standalone password with:
   ```sh
   sudo /volume1/wireguard/bin/wg-admin setpassword
   ```

## License

The `wireguard-go` source code is © 2017–2025 WireGuard LLC, MIT License.

The `admin/` directory and supporting scripts are original additions, also released under
the MIT License.

See [LICENSE](LICENSE) for the full text.

---

*Upstream wireguard-go: https://git.zx2c4.com/wireguard-go*
