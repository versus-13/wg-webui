# wg-webui

A lightweight web interface for managing WireGuard peers. Add, enable/disable, and delete peers, download their `.conf` files, and scan QR codes for mobile clients — all from a browser.

## Features

- Password protection (bcrypt hash, changeable via web or CLI)
- Peer creation with automatic IP assignment from the subnet
- Enable / disable peers without deleting them
- Download peer config or scan a QR code
- WireGuard status page (`wg show`)
- Server parameter configuration (endpoint, DNS) via the web interface
- Peers and settings stored in SQLite

## Requirements

- Go 1.21+
- WireGuard on the server (`wg`, `wg-quick`)
- A running WireGuard interface with `PrivateKey` in the config file

## Build

### For the current platform

```sh
make build
```

The version is taken automatically from the latest git tag (see [Versioning](#versioning) below).
A plain `go build .` also works but will show `dev` as the version.

### For all supported platforms

```sh
make all
```

Binaries are placed in `./dist/`:

```
dist/
  wg-webui-v1.0.0-linux-amd64
  wg-webui-v1.0.0-linux-arm64
  wg-webui-v1.0.0-linux-arm7
```

| Target | Platform |
|---|---|
| `make linux-amd64` | x86-64 servers |
| `make linux-arm64` | Raspberry Pi 4+, AWS Graviton |
| `make linux-arm` | Raspberry Pi 2/3, ARMv7 boards |

### Versioning

The version embedded in the binary comes from `git describe --tags`. To create and push a release tag:

```sh
git tag v1.0.0
git push origin v1.0.0
```

After that, `make build` produces a binary that reports `v1.0.0`.

Commits made after the tag are shown as `v1.0.0-3-gabcdef1` (3 commits ahead, hash `abcdef1`). A build with uncommitted changes gets a `-dirty` suffix.

## Running

```sh
sudo ./wg-webui \
  --wg-interface wg0 \
  --wg-config /etc/wireguard/wg0.conf \
  --listen 5000
```

Root (or `CAP_NET_ADMIN`) is required to call `wg syncconf`.

### All flags

| Flag | Default | Description |
|---|---|---|
| `--wg-interface` | `wg0` | WireGuard interface name |
| `--wg-config` | `/etc/wireguard/wg0.conf` | Path to WireGuard config file |
| `--listen` | `5000` | Web UI port (always bound to `127.0.0.1`) |
| `--db` | next to `--wg-config`, `<interface>.db` | Path to SQLite database |
| `--log` | stdout | Path to log file |
| `--reset-password` | — | Reset the password interactively and exit |

Parameters read automatically from `--wg-config`:

| Key in `[Interface]` | Usage |
|---|---|
| `Address` | Subnet for assigning IPs to peers |
| `ListenPort` | WireGuard port used in client configs |
| `PrivateKey` | Derives the server's public key |

## First run

### 1. Set a password

On first open, the app will prompt you to set a password via a web form.

Alternatively, via CLI before starting:

```sh
sudo ./wg-webui --wg-config /etc/wireguard/wg0.conf --reset-password
```

### 2. Configure server parameters

Go to **Settings** and set the public hostname (endpoint for clients) and DNS servers.

## Resetting the password

```sh
sudo ./wg-webui --wg-config /etc/wireguard/wg0.conf --reset-password
# or with an explicit database path
sudo ./wg-webui --db /opt/wg-webui/wg0.db --reset-password
```

## Logging

Logs go to stdout by default. To write to a file:

```sh
sudo ./wg-webui --wg-config /etc/wireguard/wg0.conf --log /var/log/wg-webui.log
```

| Event | Level |
|---|---|
| Start / stop | `INFO` |
| Successful login | `INFO` |
| Wrong password | `WARN` |
| Peer added | `INFO` |
| Peer deleted | `INFO` |

### Log rotation (logrotate)

```
/var/log/wg-webui.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP wg-webui.service
    endscript
}
```

Without systemd: `kill -HUP $(pidof wg-webui)`

## Running behind a reverse proxy

The web interface listens only on `127.0.0.1:<port>`. Point nginx/Caddy at that address and keep the port closed to the outside.

## License

MIT — see [LICENSE](LICENSE).
