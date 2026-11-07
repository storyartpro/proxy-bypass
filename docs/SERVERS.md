# Linux servers

Servers are optional for the workstation: the PC works with its own proxies alone. A server is
useful when the same blocked resources must also be reachable *from that server* (bots, crawlers,
scheduled jobs), and when its network should send those destinations through a SOCKS5 proxy.

## Requirements

- Linux with systemd, `iptables`, `ip6tables`.
- root or `sudo` **without a password** (`sudo -n true` must succeed).
- A working `redsocks` with a SOCKS5 upstream in `/etc/redsocks.conf` (for the routing itself).
- SSH alias in `~/.ssh/config` on the PC, key-based login without a password prompt.

## Adding a server

1. Add the alias to `~/.ssh/config`, verify `ssh <alias> 'echo ok'` works.
2. In the app: **Серверы / Servers** → enter the alias → **Добавить / Add**.
   The app checks the connection before saving.

## Install the daemon

Press **Установить / Install**. The app uploads:

- `/usr/local/sbin/proxy-bypass` — the daemon (`app/assets/proxy-bypass.py`, stdlib only);
- `/etc/proxy-bypass/config.json` — configuration, `watch` seeded with the blocked list;
- `/etc/systemd/system/proxy-bypass.service` — systemd unit;

then runs `systemctl daemon-reload` and `systemctl enable --now proxy-bypass`.

The daemon creates its own chains `PROXY-BYPASS` / `PROXY-BYPASS6` and inserts the jump **after**
existing DNAT rules and **before** any legacy redirect chain, so pre-existing behaviour is not
broken. Verdicts and rules are rebuilt on every sync; the service survives reboots.

## Control

| Button | Remote command |
| --- | --- |
| Включить / Start | `systemctl start proxy-bypass` |
| Выключить / Stop | `systemctl stop proxy-bypass` |
| Передать список / Push list | `proxy-bypass add --domain <host> --pin` for each blocked host |
| Передать прокси / Push proxy | rewrite `redsocks.conf` upstream + `systemctl restart redsocks` |
| Убрать / Remove | remove the server from the app list (does not uninstall) |

Pushing the proxy writes `/etc/redsocks.conf.bak.<timestamp>` first, then updates `ip`, `port`,
`login`, `password` and restarts `redsocks`. Credentials are passed over SSH stdin only.

## Server-side details

- State: `/var/lib/proxy-bypass/state.json`.
- Config: `/etc/proxy-bypass/config.json`.
- Logs: `journalctl -u proxy-bypass -n 100`.
- Manual commands: `sudo -n /usr/local/sbin/proxy-bypass status --json`,
  `sync`, `check --domain <host>`, `add --domain <host> --pin`, `remove --domain <host>`,
  `learn`, `daemon`.
- Probes use `SO_MARK`, and a `-m mark --mark 0x1 -j RETURN` rule is kept first in `OUTPUT`, so the
  "direct" measurement is honest even while redirects are active.

## Uninstall

```bash
sudo systemctl disable --now proxy-bypass
sudo rm -f /etc/systemd/system/proxy-bypass.service /usr/local/sbin/proxy-bypass
sudo rm -rf /etc/proxy-bypass /var/lib/proxy-bypass
sudo systemctl daemon-reload
```

`iptables` chains are flushed by the daemon on removal; check `iptables -t nat -L` if you removed
the files by hand.
