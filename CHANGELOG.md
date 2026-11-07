# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [0.1.5] - 2026-11-07

### Fixed

- The app keeps its proxy credentials in sync with the local secrets file at startup and every
  five minutes. A rotated provider password used to stay forever in the DPAPI-encrypted store, so
  the only proxy was reported as "connect failed (2)" while the same credentials worked one minute
  later in a direct test.

## [0.1.4] - 2026-11-07

### Fixed

- The Start-menu shortcut opens the window again when the app is already running: the second launch
  detects the live interface before binding the routing proxy, so the busy proxy port no longer
  kills it silently.
- The installer now mirrors the `app/` tree with robocopy (`/MIR`). `Copy-Item -Recurse` into an
  existing folder silently kept old files on Windows PowerShell 5.1, so reinstalls ran stale code.
- When no proxy is healthy, blocked-list hosts fall back to a direct connection instead of failing
  every request with a 502.

## [0.1.3] - 2026-11-07

### Changed

- Proxy health checks now use a 20-second timeout and require two consecutive failed sweeps before
  the active route is dropped, so a slow provider no longer takes the bypass down instantly.

### Fixed

- The installer no longer overwrites an existing `data/config.json` in the installed location,
  keeping the user's settings and encrypted credentials intact.

## [0.1.2] - 2026-11-07

### Added

- Blocked-list entries may now be IPv4 addresses and CIDR subnets in addition to domains
  (for example `203.0.113.7` or `198.51.100.0/24`). The router pins every address inside a subnet,
  and servers receive such entries as iptables rules via the new daemon command
  `add-ip --cidr <subnet>` / `remove-ip --cidr <subnet>`.
- `app/core/targets.mjs`: shared validation for domains, IPv4 addresses and CIDR matching.
- Unit tests for target validation, CIDR matching and the mixed-list split.

### Fixed

- The daemon no longer refuses to start when its watch list contains a malformed or non-domain
  entry: invalid items are skipped instead of aborting config load.
- Server install now passes only domains to the daemon watch list and re-applies static subnets
  with `add-ip` after the restart.

## [0.1.1] - 2026-11-07

### Added

- Windows DPAPI encryption for stored proxy passwords (`passwordEnc` in `config.json`); plaintext
  passwords are migrated on the next save.
- Sparkline charts for proxy latency and speed in the monitoring tab.
- Documentation screenshots rendered with demo data, and a GitHub Pages landing page.

### Security

- Proxy credentials are no longer written to disk in plain text when DPAPI is available.

## [0.1.0] — 2026-11-07

First public release.

### Added

- Windows 11 app: local routing proxy on `127.0.0.1:38080`, web UI in a separate window
  (`127.0.0.1:8077`), silent launcher and installer with autostart.
- Up to five SOCKS5 proxies in priority order with health checks every 20 seconds and automatic
  failover to the next healthy proxy.
- Per-host routing: forced blocked list, always-direct hosts, loopback and private ranges excluded,
  background classification for unknown hosts.
- SOCKS5 client implemented as a single incremental parser supporting domain, IPv4 and IPv6
  destinations; concurrent handshakes capped to avoid provider throttling.
- Shared blocked-host list with manual editing, one-click push to any managed server and optional
  automatic push after scanning.
- Automatic scanner: direct-vs-proxy probing adds resources blocked on the main IP to the list.
- Monitoring: main external IP (address, country, organisation, latency) and per-proxy latency,
  download speed, stability and connection load, with history.
- Server management over SSH: install/update the Linux daemon, start/stop/restart it per server,
  push the blocked list, push proxy credentials by rewriting the `redsocks` upstream with a
  timestamped backup.
- Linux daemon (`proxy-bypass.py`): own iptables chains, honest `SO_MARK` probing, geo-block body
  detection, DoH fallback, log learning, JSON status.
- Single-instance behaviour: launching the shortcut again reopens the window of the running app.
- Documentation: English and Russian READMEs, architecture, Windows setup, server guide,
  contributing and security notes.

### Security

- Proxy credentials stay in the local `data/` directory (ignored by git) and are sent to servers
  over SSH stdin only.
- UI and routing proxy listen on loopback only.
- Windows system proxy settings are snapshotted and restored when bypass is disabled.

### Known limitations

- Node.js 20+ is required to run the app (single-file `.exe` is planned).
- Proxy credentials are stored in plain text on the workstation (DPAPI encryption planned).
- Desktop applications that ignore the Windows system proxy need their own proxy configuration.
- Only SOCKS5 upstreams are supported.

[0.1.0]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.0
[0.1.1]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.1
[0.1.2]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.2
[0.1.1]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.1
[0.1.3]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.3
[0.1.4]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.4
[0.1.5]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.5
