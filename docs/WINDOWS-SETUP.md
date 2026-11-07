# Windows setup

## Requirements

- Windows 11 (Windows 10 works as well).
- Node.js **20 or newer** in `PATH` (`node --version`).
- OpenSSH client and `~/.ssh/config` aliases for the servers you want to manage.
- At least one SOCKS5 proxy with host, port, login and password.
- Microsoft Edge or Google Chrome for the app window (the app can also be opened in any browser).

## First run

```cmd
start.cmd
```

- The window opens with the app UI (`http://127.0.0.1:8077`).
- The routing proxy listens on `127.0.0.1:38080`.
- `data/config.json` is created on first run. Put your proxy into the **Прокси / Proxies** tab:
  host, port, login, password. Save.
- The status dot next to the proxy shows whether the health check passed.

## Enable bypass on the PC

Press **Включить на ПК / Enable on PC**. The app snapshots the current Windows proxy settings and
points the system proxy at `127.0.0.1:38080`. Disabling restores exactly what was there before.

Keep in mind:

- Applications that ignore the Windows system proxy (some Electron/Qt apps) will not use the
  bypass; configure their own proxy setting if they support it.
- If the app is not running, the system proxy points at a dead port. Start the app from the Start
  menu — the listener comes back and browsing works again.

## Install with autostart

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

The installer:

1. copies the app to `%LOCALAPPDATA%\ProxyApp` (keeps your `data/config.json` if it exists);
2. creates a Start-menu shortcut **Proxy Bypass**;
3. creates a Startup shortcut so the app starts when you sign in — no administrator rights needed.

Remove autostart by deleting `Proxy Bypass.lnk` from
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.

## Serving and files

| Path | Purpose |
| --- | --- |
| `%LOCALAPPDATA%\ProxyApp` | installed application |
| `%LOCALAPPDATA%\ProxyApp\data\config.json` | settings (contains proxy credentials — keep local) |
| `%LOCALAPPDATA%\ProxyApp\data\app.log` | application log |
| `%LOCALAPPDATA%\ProxyApp\data\monitor.json` | monitoring history |
| `%LOCALAPPDATA%\ProxyApp\data\local-state.json` | learned host verdicts |

## Troubleshooting

**Window does not open.** Run `start.cmd` from the installed folder; it prints the error to the
console. Also check whether another instance is running: `Get-Process node` — a running instance is
normal, the window should just reopen.

**Ports busy.** `netstat -ano | findstr :8077` shows the owner. Change `appPort` in
`data/config.json` and the `PROXY_APP_PORT` used by the launcher if needed.

**Proxy marked unavailable.** Check host/port/credentials. Some providers reject connections from
new IPs or have connection limits; the monitoring tab shows latency and errors.

**System proxy left pointing at a dead port.** Turn the PC toggle off (the app restores settings),
or start the app again. Restoring manually: Settings → Network & Internet → Proxy →
"Automatically detect settings" on, manual proxy off.
