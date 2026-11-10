# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/).

## [0.5.1] - 2026-11-10

### Fixed

- Запуск больше не завершается, если порт локального прокси занят посторонним процессом:
  интерфейс и API поднимаются сразу, а привязка порта повторяется каждые 10 секунд до успеха
  (раньше `EADDRINUSE` трактовался как «второй экземпляр», приложение молча закрывалось и
  вместе с ним пропадали системный прокси и переменные среды).
- Отложенное включение системного прокси и переменных среды выполняется после того, как порт
  действительно освободился, поэтому «Охват ПК» не остаётся выключенным после конфликта.

### Changed

- Автозапуск: приложение ставится задачей планировщика `Proxy Bypass` с уровнем
  `HighestAvailable` (нужен для TUN) вместо ярлыка в Startup; ярлык удалён.

## [0.5.0] - 2026-11-10

### Added

- **Прозрачный перехват (TUN)** — `app/core/transparent.mjs` и карточка «Прозрачный перехват»:
  движок sing-box 1.14.4 скачивается в `data/vendor/` при первом включении, поднимается
  TUN-интерфейс `proxyapp` (172.19.0.1/30, gvisor, `auto_route`), и весь трафик программ, которые
  не читают системный прокси и переменные среды, уходит в локальный маршрутизатор. DNS берётся из
  маршрута по умолчанию, UDP/QUIC отклоняется, локальные сети, SSH-хосты и адреса upstream-прокси
  идут напрямую, процесс `node.exe` исключён из перехвата (защита от петли).
- **Восстановление SNI для «сырых» IP**: локальный прокси отвечает на CONNECT к IP:443, читает
  TLS ClientHello, достаёт имя и открывает туннель по домену. SOCKS5-провайдер резолвит имя сам,
  а прямые IP Telegram у него не работают — без этого TUN-трафик Telegram получал 502.
- API: `GET /api/transparent`, `POST /api/transparent/toggle`, `POST /api/transparent/install`,
  `POST /api/relaunch-admin`; `/api/status` теперь отдаёт `transparent.{installed,elevated,running,wanted}`.
- UI: карточка «Прозрачный перехват» с индикатором, переключателем и подсказкой про права администратора.
- 9 новых тестов (41 всего).

### Changed

- `status()` возвращает полный хвост лога sing-box (80 строк) вместо 12 — диагностика больше не теряется.
- Перезапуск с правами администратора пишет `start-admin.cmd` с явными `PROXY_APP_DATA` и
  `PROXY_APP_PORT`, поэтому elevated-копия работает с установленным профилем, а не с пустым.

### Verified

- TUN поднят, `transparent.elevated=true`: `curl --noproxy '*' https://api.telegram.org/` → 302 за
  1,3 с, `/bot123:invalid/getMe` → 401, `example.com` → 200.
- TLS 1.3 рукопожатие с `api.telegram.org` через CONNECT на IP `149.154.166.110` — то есть
  SNI-маршрут работает и на реальном провайдере.

## [0.4.0] - 2026-11-10

### Added

- **PC-wide environment proxy** (`app/core/env-proxy.mjs`): one switch writes `HTTP_PROXY`,
  `HTTPS_PROXY` and `ALL_PROXY` into the current user's environment (HKCU\Environment) and
  broadcasts `WM_SETTINGCHANGE`, so console tools, git, pip, npm and Python requests reach the local
  router. `NO_PROXY` is preserved and always contains loopback. Previous values are backed up to
  `env-proxy-backup.json`; disabling restores them exactly, or removes only the three managed
  variables when no backup exists.
- **Default route mode** in `LocalRouter`: `direct` (historical) or `proxy`. In `proxy` mode an
  unknown host goes through the proxy immediately instead of being tried directly first; loopback,
  private addresses and the always-direct whitelist (`deepseek.com`) still go direct, and the route
  falls back to direct while the upstream is unavailable.
- API: `GET /api/env`, `POST /api/env/toggle`, `GET /api/router`, `POST /api/router/mode`;
  `/api/status` now reports `pc.envEnabled` and `router.{mode,upstreamAvailable,forcedCount}`.
- UI: «Охват ПК» card on the Прокси tab — environment toggle and default-route selector.
- 12 new tests (32 total).

### Changed

- Shutdown turns the environment proxy off before exiting, while the `envProxyWanted` flag keeps the
  next start re-enabling it.

### Verified

- Telegram gateway (Hermes) connects through the app: `telegram.proxy_url: http://127.0.0.1:38080`
  in each profile's `config.yaml`; `✓ telegram connected` for default, insideme and service24.

## [0.3.1] - 2026-11-08

### Added

- **Per-application route switch**: every tracked process/service now has a mode — **через прокси**
  (its discovered channels are pinned to the proxy) or **напрямую (IP)** (its channels are subtracted
  from the blocked list, even when they also exist in the manual list — direct wins). The mode is
  persisted and can be changed at any moment from the Приложения tab.
- `POST /api/apps/mode` endpoint; `mergeBlocked()` now subtracts direct-mode channels.
- Tests for the mode behaviour (20 tests total).

### Verified

- Tracking `AnyDesk.exe`: blocked list 1393 → 1394 (proxy mode).
- Switching to direct: back to 1393; switching to proxy: 1394 again; forgetting: 1393.

## [0.3.0] - 2026-11-08

### Added

- **Application tracking module** (`app/core/apps.mjs`): choose a running process or a Windows
  service, remember it, and the app keeps collecting every network channel that application opens —
  public remote IPs plus reverse-DNS names — and pins them to the proxy through the blocked list.
  Profiles can be disabled (stop contributing) or forgotten (remove their channels), with a "scan
  now" action and automatic refresh every 15 seconds while the application runs.
- New **Приложения** tab: searchable process/service lists with connection state, tracked profiles
  with running state, channel count, enable toggle and forget button.
- The blocked list is now materialised from `manualBlocked` + enabled profiles (`mergeBlocked()`),
  so removing an application never touches hand-maintained entries.
- Unit tests for the tracking helpers (19 tests total).

## [0.2.0] - 2026-11-08

### Added

- **Bulk import of the blocked list.** Paste any mix of domains, IPv4 addresses and CIDR
  subnets separated by commas, semicolons, tabs, spaces or line breaks — Excel tables and full URLs
  are accepted too (`host:port` is reduced to the host, URLs to their hostname). Duplicates are
  skipped, unparsable tokens are reported back.
- **Domain expansion.** For a given domain the app resolves its IPv4 addresses and discovers
  subdomains (certificate transparency via crt.sh, plus probing common prefixes when CT is
  unavailable), then writes the domain, all subdomains and all IPs into the blocked list. An
  optional checkbox does the same for every domain in a bulk import.
- New module `app/core/lookup.mjs`; fetching works directly and falls back to the active proxy when
  DNS or CT endpoints are filtered.
- Parser helpers `parseTargetList()` and unit tests for bulk parsing (14 tests total).

### Fixed

- The UI source in the working tree had been reverted to an older snapshot; it was restored from
  the repository before adding the new controls.

## [0.1.10] - 2026-11-07

### Fixed

- **Tray icon and menu.** The icon was created without a Windows Forms message loop, so it could
  stay invisible and its menu items never received clicks. The tray is now a real WinForms
  application (`-Sta`, `Application.Run`, a timer for backend polling): the icon appears,
  "Открыть окно" / toggle / "Закрыть полностью" work, and it always exits when the backend stops.
- **Slow startup.** The window used to open only after the proxy health sweep; with a dead proxy the
  UI stayed hidden for up to 40 seconds. The interface, window and tray now start right after the
  routing proxy, and the proxies are probed in parallel, so the window appears in about a second.
- The API no longer exposes the encrypted password blob (`passwordEnc`) to the UI.

### Verified

- `/api/pc` answers 1 s after the shortcut click; both proxies stay in the list after restarts.
- Tray child process is present, `tray.log` records clicks ("open window from tray").
- Failover keeps the healthy first proxy active while the second one times out.

## [0.1.9] - 2026-11-07

### Added

- **Tray icon.** Closing the browser window no longer ends the session: the app keeps running in
  the notification area. The tray menu can reopen the window, toggle the PC proxy and stop
  everything. The icon disappears by itself when the backend is gone.
- **"Закрыть полностью"** button in the window and in the tray: stops the local proxy, the app
  tunnel, monitoring and the scanner, restores the Windows proxy settings, and exits the process.
- The PC-proxy state is remembered: after a full shutdown and the next start, the bypass comes back
  only if it was enabled when the app was closed.

### Fixed

- The tray process is spawned with real stderr capture; a failing helper script now leaves a line in
  the application log instead of disappearing silently.

## [0.1.8] - 2026-11-07

### Fixed

- Adding or editing a proxy no longer wipes connection fields. The API used to return only the
  display view of the proxy list (endpoint, health), so the UI sent back entries without
  `host`/`port`/credentials — a newly added proxy was saved as `:0` and the existing one lost its
  password (provider answered SOCKS code 2). The API now returns the real configuration fields and
  the server keeps previous values when a field is omitted.
- Saving a SOCKS5 proxy without host or port is rejected with a clear message instead of writing a
  broken entry.
- Repaired the affected configuration: invalid entries are removed and the credentials are refreshed
  from the secrets file.

## [0.1.7] - 2026-11-07

### Fixed

- The blocked-list input had a duplicate DOM id (`new-host`, also used by the proxy form), so the
  "Добавить" button read the wrong field and silently added nothing. The field is now `new-target`.
  IPv4 addresses and subnets can be added from the UI again (verified with `104.253.1.146`).

## [0.1.6] - 2026-11-07

### Added

- Optional **local SOCKS5 tunnel for applications** (`ssh -N -D 127.0.0.1:1081`), managed by the
  app and restarted automatically if the SSH connection drops. It is intended for programs that only
  accept their own proxy setting — Telegram, for example. Enable it in the Servers tab and point the
  app at `SOCKS5 127.0.0.1:1081`.

### Fixed

- Telegram lost its proxy route when the previous tunnel provider was retired. The tunnel now lives
  in the app itself, so it survives restarts and app updates.

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
[0.1.6]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.6
[0.1.7]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.7
[0.1.8]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.8
[0.1.9]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.9
[0.1.10]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.1.10
[0.2.0]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.2.0
[0.3.0]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.3.0
[0.3.1]: https://github.com/storyartpro/proxy-bypass/releases/tag/v0.3.1
