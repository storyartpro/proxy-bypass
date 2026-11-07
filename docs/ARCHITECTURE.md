# Architecture

Proxy Bypass has two planes that must not be confused:

- **Data plane** — the workstation's traffic. It goes through the local routing proxy and, when
  needed, directly to one of the configured SOCKS5 proxies. Servers are *not* part of this path.
- **Control plane** — the app talks to Linux servers over SSH to install the daemon, toggle it, and
  push the blocked-host list and proxy credentials. User traffic never flows over SSH.

## Components

```
app/server.mjs
├── LocalRouter            app/core/local-proxy.mjs   per-host verdicts + forced list
├── createLocalProxy       app/core/local-proxy.mjs   HTTP CONNECT / absolute-form proxy
├── UpstreamManager        app/core/upstreams.mjs     proxy pool, health checks, failover
├── Monitor                app/core/monitor.mjs       main IP + per-proxy metrics
├── scanner                app/server.mjs             direct-vs-proxy classification
├── servers                app/core/servers.mjs       SSH install/control/push
└── HTTP API + UI          app/ui/                    loopback only (127.0.0.1:8077)
```

## Routing decision

For every request the router asks `LocalRouter.routeFor(host, port)`:

1. loopback, private ranges, `*.local`, `localhost` → **direct**;
2. `deepseek.com` (the harness/account endpoints) → **direct**, so control traffic never leaves
   through a foreign exit;
3. host present in the forced set (the blocked-host list from the UI) → **proxy**. Entries may be
   domains, IPv4 addresses or CIDR subnets; a subnet pins every address inside it and is checked
   before the cached verdict;
4. cached verdict → proxy only when the verdict is `blocked`;
5. IP literal → reachability probe (direct TCP, then SOCKS) with a 15-minute cache;
6. unknown domain → **direct now**, classification in the background. The next request already
   knows the answer, and no page waits for a probe.

Classification (`classify`) probes the host directly and through the active proxy:

- direct answer (< 500, not 403/451) → `direct`;
- direct 403/451 whose body carries a geo-block marker → `blocked`;
- direct refusal but a *different* answer through the proxy → `blocked`;
- both fail → `unreachable` (kept direct).

## SOCKS5 client

`app/core/local-proxy.mjs` implements a single incremental parser for the whole handshake:

- greeting offers no-auth and username/password when credentials exist;
- CONNECT supports domain (ATYP 3), IPv4 (ATYP 1) and IPv6 (ATYP 4) destinations;
- the reply is consumed by one `data` listener with a buffer, so no bytes can be lost between
  steps. An earlier listener-per-step version dropped bytes and stalled handshakes for 10–15 s.

Concurrent SOCKS handshakes are capped (`maxSocks`) because providers throttle bursts.

## Failover

`UpstreamManager` keeps the ordered proxy list, probes each enabled proxy through
`www.google.com:443` (8 s timeout) and marks the first healthy one active. A refresh runs every
20 s; when the active proxy fails the next healthy one takes over and the router's upstream is
swapped. Disabled entries are skipped. All proxies are ordinary SOCKS5 endpoints; an SSH type exists
in the type union but is not offered in the UI — the workstation must not route through servers.

## Credentials at rest

Proxy passwords are encrypted with Windows DPAPI (`app/core/dpapi.mjs`) for the current Windows
account and stored as `passwordEnc` in `data/config.json`. Encryption runs through PowerShell's
`ProtectedData` (Node has no DPAPI binding); the plaintext is passed over stdin and the ciphertext
comes back as base64. On load, `loadConfigAsync()` decrypts the stored values into memory only, so
routing uses plaintext while the file keeps ciphertext. On a non-Windows host DPAPI is unavailable
and the file keeps plaintext (development only).

## Monitoring

Every `intervalSec` (default 60) the monitor records:

- **main IP** — direct request to `https://ipinfo.io/json`: address, country, city, organisation,
  latency;
- **per proxy** — SOCKS handshake latency, real HTTPS download speed from
  `speed.cloudflare.com/__down?bytes=…`, stability (successes / samples, window 20), connection
  load (router stats), last error.

History is capped by `historyLimit` and stored in `data/monitor.json`. The UI renders the last
samples as sparklines (latency and speed) above the per-proxy cards.

## Server side

`assets/proxy-bypass.py` (stdlib only) runs on Linux as `proxy-bypass.service`:

- keeps its own chains `PROXY-BYPASS` / `PROXY-BYPASS6`, leaving any existing redirector untouched;
- probes destinations directly with `SO_MARK` (a mark-RETURN rule is kept at the top of `OUTPUT` so
  probes stay honest) and through the server's SOCKS5 proxy;
- routes only measured-blocked destinations, writes iptables REDIRECT rules per address;
- persists verdicts in `/var/lib/proxy-bypass/state.json`, learns from logs, and re-checks on a
  timer.

The app manages it with `ssh` + `sudo -n`:

| Action | Remote effect |
| --- | --- |
| install | upload daemon/unit/config, `systemctl enable --now proxy-bypass` |
| start / stop / restart | `systemctl <action> proxy-bypass` |
| push list | `proxy-bypass add --domain <host> --pin` per host |
| push proxy | rewrite `/etc/redsocks.conf` (timestamped backup) and restart `redsocks` |

Uploads use `base64 -d` over SSH stdin; proxy credentials are embedded in the stdin script, never
on a command line.

## Threading and lifecycle

The app is one Node process with event-loop concurrency: no worker threads. Timers are `unref()`ed
so they never keep the process alive on shutdown. The proxy listener, failover timer, scanner timer
and monitor timer are independent; a failure in any of them is logged and never stops routing.

A second app instance detects `EADDRINUSE` on `127.0.0.1:8077`, opens the window of the running
instance and exits.
