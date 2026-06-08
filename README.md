# WireGuard for Synology RT6600AX (SRM / Linux 4.4.x)

This is a fork of [wireguard-go](https://git.zx2c4.com/wireguard-go) patched to work on
Synology SRM routers running Linux kernel 4.4.x (tested on the RT6600AX with kernel 4.4.60,
aarch64 / MT7986A).

## Kernel 4.4.x epoll workaround

**Root cause**: Go's epoll implementation uses `EPOLLET` (edge-triggered mode). On kernel
4.4.60, `epoll_wait` never delivers `EPOLLIN` events for UDP sockets. `ppoll`/`poll` are
equally broken for UDP readiness notification on this kernel.

**Fix**: `conn/legacyrecv_linux.go` replaces the standard `makeReceiveIPv4/IPv6` functions
with a `SetReadDeadline`-based poll loop. Go's timer mechanism is independent of epoll — it
wakes the goroutine unconditionally after a 10 ms deadline, at which point a non-blocking
`ReadMsgUDP` drains any packet that arrived since the last wakeup. Maximum added latency per
packet is 10 ms. The legacy path is selected at startup by `conn/batchread_linux.go` when the
kernel major version is less than 5.

The standard batched-read path is used on Linux ≥ 5.x and all other platforms.

## Synology SRM notes

- `WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1` is required: SRM kernel 4.4.60 reports
  native WireGuard support in `/sys/module/wireguard`, but the module is not loaded. Without
  this env var, wireguard-go refuses to start.
- The `tun` kernel module may need to be loaded: `insmod /lib/modules/tun.ko`.
- SRM does not manage NAT for custom subnets — the init script adds a `MASQUERADE` rule for
  the VPN subnet manually.
- SRM's `INPUT_FIREWALL` iptables chain controls inbound access. The init script adds a rule
  for the WireGuard listen port; this can also be added via the SRM Security → Firewall GUI
  for persistence across SRM updates.

## Deployment

### Prerequisites

- Cross-compile toolchain: `aarch64-linux-gnu-gcc`
- Go toolchain

### Build

```
make
```

This produces `bin/wireguard-go` (aarch64) and `bin/wg`.

### Deploy to router

```
./deploy.sh [router-ip] [router-user]
# default: ./deploy.sh 172.16.2.1 jamiet
```

The script copies binaries, init script, and `restore.sh` to `/volume1/wireguard/` on the
router. If no config exists yet, it will prompt you to create one from
`config/wg0.conf.example`.

### Config

Copy `config/wg0.conf.example` to `/volume1/wireguard/wg0.conf` and fill in real keys.
Generate a key pair with:

```
wg genkey | tee private.key | wg pubkey
```

The `#Address = 10.10.0.x/24` comment at the top is parsed by the init script to assign the
interface address — it is not a standard `wg setconf` field.

### Start / stop

```sh
sudo /usr/local/etc/rc.d/wireguard.sh start
sudo /usr/local/etc/rc.d/wireguard.sh stop
sudo /usr/local/etc/rc.d/wireguard.sh status
```

---

# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go.

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
