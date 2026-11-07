#!/usr/bin/env python3
"""proxy-bypass — route exactly the resources blocked from this host through a SOCKS5 proxy.

The host is (typically) a Russian VPS: some external services are unreachable
directly.  A transparent redirector (redsocks) already listens on a local port;
this program decides *which* destination addresses must be redirected.

How a verdict is reached (never from a single HTTP error):

  1. resolve the domain (system DNS, then DNS-over-HTTPS through the proxy when
     system DNS is itself blocked / poisoned);
  2. probe the destination *directly*, bypassing our own iptables REDIRECT rules
     with SO_MARK so the measurement is honest even for already-routed hosts;
  3. probe the same destination through the SOCKS5 proxy;
  4. direct fails at DNS/TCP/TLS level (or returns an explicit 403/451) AND the
     proxy path returns a real HTTP status  ->  ``blocked``  ->  add the current
     addresses to the redirect chain;
     direct works  ->  ``direct``  ->  nothing is added (and, after two
     consecutive direct verdicts, a non-pinned host is removed again);
     both paths fail  ->  ``unreachable``  ->  nothing is added (the service is
     probably down, so we do not mislabel it as blocked).

A separate iptables chain (``PROXY-BYPASS``) is used, jumped before the legacy
``CURSOR-PROXY`` chain, so an existing refresh cron can keep working untouched.

Only the Python standard library is used; the daemon runs as root from systemd.
"""

from typing import Dict, List, Optional, Set, Tuple

import argparse
import concurrent.futures
try:  # Linux daemon; Windows is only used to import this module in tests.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None
import glob
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

# Python 3.6 (Ubuntu 18.04) has no ssl.SSLCertVerificationError; its TLS failures
# arrive as a plain SSLError, which the same handler already covers.
if not hasattr(ssl, "SSLCertVerificationError"):
    ssl.SSLCertVerificationError = ssl.SSLError

CONFIG_PATH = Path(os.environ.get("PROXY_BYPASS_CONFIG", "/etc/proxy-bypass/config.json"))
STATE_PATH = Path(os.environ.get("PROXY_BYPASS_STATE", "/var/lib/proxy-bypass/state.json"))
LOCK_PATH = Path(os.environ.get("PROXY_BYPASS_LOCK", "/run/proxy-bypass.lock"))
SO_MARK = getattr(socket, "SO_MARK", 36)
MARK_BIT = 0x1
USER_AGENT = "proxy-bypass/1.0 (+server-side reachability probe)"

DEFAULT_CONFIG = {
    "version": 1,
    "chain": "PROXY-BYPASS",
    "chain6": "PROXY-BYPASS6",
    "redsocks_conf": "/etc/redsocks.conf",
    "redsocks_port": 12345,
    "ports": [443],
    "timeout_s": 6.0,
    "interval_min": 15,
    "learn_every": 4,
    "probe_path": "/",
    "workers": 8,
    "watch": [
        "openrouter.ai",
        "api.openai.com",
        "chatgpt.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com",
        "huggingface.co",
        "api.github.com",
        "raw.githubusercontent.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "registry-1.docker.io",
        "discord.com",
        "api.notion.com",
        "api.slack.com",
        "www.figma.com",
    ],
    # api.telegram.org is deliberately absent: in this setup the platform's
    # traffic is DNAT'ed to another Telegram address, and a transparent
    # redirect would break the gateway's bot transport instead of unblocking.
    "ignore": [
        "localhost",
        "localdomain",
        "telegram.org",
        "api.telegram.org",
        "t.me",
        "telegram.me",
        "vk.com",
        "yandex.ru",
        "ya.ru",
        "mail.ru",
        "sber.ru",
        "gosuslugi.ru",
    ],
    "doh": {
        "enabled": True,
        "host": "cloudflare-dns.com",
        "path": "/dns-query",
    },
    "learn": {
        "enabled": True,
        "globs": [
            "/home/*/.hermes/logs/*.log",
            "/var/log/redsocks.log",
        ],
        "max_lines": 4000,
        "max_new": 8,
    },
}

DOMAIN_RE = re.compile(
    r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)
URL_HOST_RE = re.compile(r"https?://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)", re.I)
BARE_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59}))\b", re.I
)
ERROR_MARKERS = (
    "timed out", "timeout", "etimedout", "econnreset", "econnrefused",
    "connection reset", "connection refused", "could not resolve",
    "getaddrinfo", "name or service not known", "tls", "handshake",
    "ssl", "fetch failed", "network error", "unreachable", "451",
    "403 forbidden", "blocked", "client network socket disconnected",
)

# A 403 is ambiguous: it can be an ordinary permission error or the service
# refusing a whole country.  Only the second kind is worth a proxy rule, and
# the answer body is the only reliable discriminator.
GEO_BLOCK_MARKERS = (
    "unsupported_country_region_territory",
    "country, region, or territory not supported",
    "country or region not supported",
    "not available in your country",
    "not available in your region",
    "isn't available in your country",
    "is not available in your",
    "unsupported_country",
    "country_not_supported",
    "region_not_supported",
    "unavailable_for_legal_reasons",
    "451 unavailable for legal reasons",
    "geo-restricted",
    "geo restricted",
    "blocked in your region",
)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", file=sys.stderr, flush=True)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json_atomic(path: Path, value, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def run(cmd, *, timeout: float = 20.0):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout, check=False)


def valid_domain(value: str) -> str:
    domain = (value or "").strip().strip(".").lower()
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"not a valid domain: {value!r}")
    return domain


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def merge_config(raw: dict) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if not isinstance(raw, dict):
        return cfg
    for key, value in raw.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    # normalise; a malformed watch entry must never make the daemon unable to
    # start, so invalid items are skipped instead of raising.
    clean_watch = []
    for item in cfg.get("watch", []):
        try:
            domain = valid_domain(item)
        except ValueError:
            continue
        if domain not in clean_watch:
            clean_watch.append(domain)
    cfg["watch"] = clean_watch
    cfg["ignore"] = [str(x).lower() for x in cfg.get("ignore", [])]
    cfg["ports"] = sorted({int(p) for p in cfg.get("ports", [443])})
    cfg["timeout_s"] = float(cfg.get("timeout_s", 6.0))
    cfg["workers"] = max(1, min(32, int(cfg.get("workers", 8))))
    return cfg


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise SystemExit(f"config not found: {CONFIG_PATH}")
    return merge_config(read_json(CONFIG_PATH, {}))


def read_redsocks(cfg: dict) -> dict:
    """Proxy endpoint and credentials live in redsocks.conf — one source of truth."""
    path = Path(cfg.get("redsocks_conf", "/etc/redsocks.conf"))
    values = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise SystemExit(f"cannot read {path}: {error}")
    for line in text.splitlines():
        match = re.match(r"\s*(ip|port|type|login|password|local_port)\s*=\s*([^;]+);", line)
        if match:
            values[match.group(1)] = match.group(2).strip().strip('"')
    if "ip" not in values or "port" not in values:
        raise SystemExit(f"no proxy endpoint in {path}")
    values["local_port"] = int(values.get("local_port", cfg.get("redsocks_port", 12345)))
    return values


# --------------------------------------------------------------------------- #
# network probes
# --------------------------------------------------------------------------- #
def resolve_direct(domain: str, family: int = socket.AF_INET) -> List[str]:
    try:
        infos = socket.getaddrinfo(domain, 443, family, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def socks5_connect(proxy: dict, host: str, port: int, timeout: float) -> socket.socket:
    """Open a SOCKS5 CONNECT tunnel; the host name is resolved by the proxy."""
    sock = socket.create_connection((proxy["ip"], int(proxy["port"])), timeout=timeout)
    sock.settimeout(timeout)
    try:
        login = proxy.get("login") or ""
        password = proxy.get("password") or ""
        methods = b"\x00\x02" if login else b"\x00"
        sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
        reply = _recv_exact(sock, 2)
        if reply[0] != 5:
            raise OSError("malformed SOCKS5 greeting")
        method = reply[1]
        if method == 0x02:
            user = login.encode()
            secret = password.encode()
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
            auth = _recv_exact(sock, 2)
            if auth[1] != 0:
                raise OSError("SOCKS5 authentication rejected")
        elif method != 0x00:
            raise OSError("SOCKS5 offers no acceptable auth method")
        name = host.encode("idna")
        request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + int(port).to_bytes(2, "big")
        sock.sendall(request)
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError(f"SOCKS5 CONNECT failed with code {head[1]}")
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        elif atyp == 4:
            _recv_exact(sock, 16)
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise OSError("connection closed early")
        buffer += chunk
    return buffer


def resolve_doh(domain: str, cfg: dict, proxy: dict) -> List[str]:
    """Resolve through DoH carried inside the SOCKS5 tunnel (used when DNS is blocked)."""
    doh = cfg.get("doh") or {}
    if not doh.get("enabled", True):
        return []
    host = doh.get("host", "cloudflare-dns.com")
    path = doh.get("path", "/dns-query")
    timeout = cfg["timeout_s"]
    sock = socks5_connect(proxy, host, 443, timeout)
    try:
        context = ssl.create_default_context()
        tls = context.wrap_socket(sock, server_hostname=host)
        query = f"{path}?name={urllib.parse.quote(domain)}&type=A"
        request = (
            f"GET {query} HTTP/1.1\r\nHost: {host}\r\n"
            f"Accept: application/dns-json\r\nUser-Agent: {USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        )
        tls.sendall(request.encode())
        payload = b""
        while len(payload) < 65536:
            try:
                chunk = tls.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            payload += chunk
            if b"\r\n\r\n" in payload and b'"Answer"' in payload:
                break
        tls.close()
    finally:
        try:
            sock.close()
        except OSError:
            pass
    _, _, body = payload.partition(b"\r\n\r\n")
    try:
        answer = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return []
    return sorted({
        item.get("data")
        for item in answer.get("Answer", [])
        if item.get("type") == 1 and isinstance(item.get("data"), str)
    })


def _probe_http(tls: ssl.SSLSocket, domain: str, path: str) -> dict:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {domain}\r\n"
        f"User-Agent: {USER_AGENT}\r\nAccept: */*\r\nRange: bytes=0-0\r\nConnection: close\r\n\r\n"
    )
    tls.sendall(request.encode())
    buffer = b""
    while len(buffer) < 8192:
        try:
            chunk = tls.recv(4096)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        buffer += chunk
        if b"\r\n\r\n" in buffer and len(buffer) >= 2048:
            break
    line = buffer.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
    if not match:
        return {"ok": False, "stage": "http", "detail": "no HTTP status line", "status": None}
    _, _, body = buffer.partition(b"\r\n\r\n")
    excerpt = body[:2048].decode("utf-8", "replace")
    return {"ok": True, "stage": "http", "detail": line.strip(), "status": int(match.group(1)),
            "body": excerpt}


def probe(domain: str, cfg: dict, *, via_proxy: bool, proxy: dict, ips: Optional[List[str]] = None) -> dict:
    """One measurement.  Returns {via, ok, stage, detail, status, ips}."""
    timeout = cfg["timeout_s"]
    result = {"via": "proxy" if via_proxy else "direct", "ok": False, "stage": None,
              "detail": None, "status": None, "ips": list(ips or [])}
    sock = None
    try:
        if via_proxy:
            sock = socks5_connect(proxy, domain, 443, timeout)
        else:
            addresses = list(ips or [])
            if not addresses:
                result["stage"] = "dns"
                result["detail"] = "no address"
                return result
            last_error = None
            for address in addresses[:3]:
                candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                candidate.settimeout(timeout)
                try:
                    candidate.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK_BIT)
                except OSError:
                    pass
                try:
                    candidate.connect((address, 443))
                    sock = candidate
                    break
                except OSError as error:
                    last_error = error
                    candidate.close()
            if sock is None:
                result["stage"] = "connect"
                result["detail"] = f"{type(last_error).__name__}: {last_error}"
                return result
        result["stage"] = "tls"
        context = ssl.create_default_context()
        tls = context.wrap_socket(sock, server_hostname=domain)
        sock = None
        try:
            result.update(_probe_http(tls, domain, cfg.get("probe_path", "/")))
        finally:
            try:
                tls.close()
            except OSError:
                pass
        return result
    except ssl.SSLCertVerificationError as error:
        result.update(stage="tls", detail=f"certificate verification: {error}")
    except ssl.SSLError as error:
        result.update(stage="tls", detail=f"TLS failure: {error}")
    except (socket.timeout, TimeoutError):
        result.update(stage="tls" if result["stage"] == "tls" else result["stage"] or "connect",
                      detail="timeout")
    except ConnectionResetError as error:
        result.update(stage="tls" if result["stage"] == "tls" else "connect", detail=f"reset: {error}")
    except OSError as error:
        result.update(stage=result["stage"] or "connect", detail=f"{type(error).__name__}: {error}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return result


def _reachable(measurement: dict) -> bool:
    return bool(measurement.get("ok")) and measurement.get("status") not in (403, 451)


def _serves(measurement: dict) -> bool:
    """True only when the proxy path produced a real (non-refusal) HTTP answer.

    A 421/403 through the proxy is not "access restored": it is the same
    policy edge answering.  Routing such a host through the proxy would not
    give the user anything, so it must not count as a bypass.
    """
    status = measurement.get("status")
    if not measurement.get("ok") or status is None:
        return False
    if status in (403, 421, 451):
        return False
    return status < 500


def _geo_blocked(measurement: dict) -> bool:
    """True when a refusal body says the whole country/region is not served.

    Such a host is unreachable from this server no matter which credentials
    are used, so it belongs behind the proxy even when the proxy path itself
    answers with an odd status (Cloudflare 421 for a blank root path).
    """
    if measurement.get("status") not in (403, 451):
        return False
    body = (measurement.get("body") or "").lower()
    return any(marker in body for marker in GEO_BLOCK_MARKERS)


def classify(domain: str, cfg: dict, proxy: dict) -> dict:
    """Direct + proxy measurement and a final verdict."""
    direct_ips = resolve_direct(domain)
    used_doh = False
    if not direct_ips:
        try:
            direct_ips = resolve_doh(domain, cfg, proxy)
            used_doh = bool(direct_ips)
        except Exception:  # noqa: BLE001 - a failed DoH attempt is just "no address"
            direct_ips = []
    direct = probe(domain, cfg, via_proxy=False, proxy=proxy, ips=direct_ips)
    direct["resolved_via"] = "doh-proxy" if used_doh else ("system" if direct_ips else "none")
    proxy_measurement = probe(domain, cfg, via_proxy=True, proxy=proxy)
    proxy_measurement["ok"] = bool(proxy_measurement.get("ok"))

    direct_ok = _reachable(direct)
    proxy_ok = bool(proxy_measurement.get("ok"))
    if direct_ok:
        verdict = "direct"
    elif _geo_blocked(direct):
        # The host answered, but it answered "your country is not served".
        verdict = "blocked"
    elif direct.get("ok") and direct.get("status") in (403, 451):
        # Direct reached the host but got an explicit refusal.  Only a real
        # answer through the proxy proves a network-level restriction; a
        # different refusal (403/421/...) is the service's own policy.
        verdict = "blocked" if _serves(proxy_measurement) else "direct"
    elif proxy_ok:
        verdict = "blocked"
    else:
        verdict = "unreachable"

    addresses = [ip for ip in direct_ips if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip)]
    addresses6 = resolve_direct(domain, socket.AF_INET6)
    return {
        "domain": domain,
        "verdict": verdict,
        "direct": direct,
        "proxy": proxy_measurement,
        "ips": addresses,
        "ips6": addresses6,
    }


# --------------------------------------------------------------------------- #
# routing rules
# --------------------------------------------------------------------------- #
def _iptables(binary: str, *args: str) -> int:
    return run([binary, *args]).returncode


def _ensure_mark_rule(binary: str, table: Tuple[str, ...], mark: str) -> bool:
    """Keep exactly one `-m mark --mark <bit> -j RETURN` at the very top of OUTPUT.

    It must precede every jump to a redirect chain, otherwise our own SO_MARK
    probes would be redirected too and the "direct" measurement would be a lie.
    """
    spec = [*table, "-m", "mark", "--mark", mark, "-j", "RETURN"]
    # Fast path: already present at position 1 (OUTPUT's first -A line).
    listing = run([binary, *table, "-S", "OUTPUT"])
    lines = [line for line in listing.stdout.splitlines() if line.startswith("-A OUTPUT")]
    if lines and "mark" in lines[0] and f"--mark {mark}" in lines[0] and "RETURN" in lines[0]:
        return False
    # Drop any existing copy (anywhere) and insert a fresh one at the top.
    while run([binary, *table, "-C", "OUTPUT", *spec]).returncode == 0:
        run([binary, *table, "-D", "OUTPUT", *spec])
    run([binary, *table, "-I", "OUTPUT", "1", *spec])
    return True


_NON_CHAIN_TARGETS = frozenset(
    {"ACCEPT", "DROP", "REJECT", "RETURN", "DNAT", "SNAT", "MASQUERADE", "LOG", "MARK", "TCPMSS"}
)


def _ensure_jump(binary: str, table: Tuple[str, ...], chain: str, port: Optional[int]) -> None:
    """Point OUTPUT at our chain before any legacy jump (e.g. CURSOR-PROXY).

    The jump must come after the SO_MARK bypass (so probes stay honest) but
    *before* an existing terminal jump such as ``-j CURSOR-PROXY``.  It must
    also come after pre-existing DNAT rules: a transparent redirect of a host
    that is deliberately DNAT'ed elsewhere (Telegram in this setup) would break
    that service instead of unblocking it.
    """
    if port is None:
        check_tail: List[str] = []
    else:
        check_tail = ["-p", "tcp", "--dport", str(port)]
    # Drop stale copies first: their position may predate a DNAT rule that was
    # installed later, and a duplicate jump would bypass that rule.
    while run([binary, *table, "-C", "OUTPUT", *check_tail, "-j", chain]).returncode == 0:
        run([binary, *table, "-D", "OUTPUT", *check_tail, "-j", chain])
    listing = run([binary, *table, "-S", "OUTPUT"])
    lines = [line for line in listing.stdout.splitlines() if line.startswith("-A OUTPUT")]
    position = len(lines) + 1
    for index, line in enumerate(lines, start=1):
        parts = line.rsplit(" -j ", 1)
        if len(parts) != 2:
            continue
        # DNAT/SNAT rules carry their destination after the target name; only
        # the first token is the target itself.
        target = parts[1].split()[0] if parts[1].strip() else ""
        if target in _NON_CHAIN_TARGETS or target == chain:
            continue
        position = index
        break
    run([binary, *table, "-I", "OUTPUT", str(position), *check_tail, "-j", chain])


def ensure_mark_bypass() -> List[str]:
    """Our own probe sockets carry SO_MARK and must skip the REDIRECT chains."""
    changed = []
    mark = f"0x{MARK_BIT:x}"
    if _ensure_mark_rule("iptables", ("-t", "nat"), mark):
        changed.append("iptables nat OUTPUT mark bypass (re)inserted")
    if _ensure_mark_rule("ip6tables", (), mark):
        changed.append("ip6tables OUTPUT mark bypass (re)inserted")
    return changed


def apply_rules(cfg: dict, entries: dict, subnets: Optional[List[str]] = None) -> dict:
    """Rebuild both redirect chains from the current state (fail-open)."""
    chain = cfg["chain"]
    chain6 = cfg["chain6"]
    port = int(cfg["redsocks_port"])
    active = [e for e in entries.values() if e.get("active")]
    ipv4 = sorted({ip for entry in active for ip in entry.get("ips", [])})
    ipv6 = sorted({ip for entry in active for ip in entry.get("ips6", [])})
    static_subnets = sorted({str(item).strip() for item in (subnets or []) if str(item).strip()})
    ensure_mark_bypass()

    _iptables("iptables", "-t", "nat", "-N", chain)
    for proto_port in cfg["ports"]:
        _ensure_jump("iptables", ("-t", "nat"), chain, int(proto_port))
    _iptables("iptables", "-t", "nat", "-F", chain)
    for subnet in static_subnets:
        for proto_port in cfg["ports"]:
            _iptables("iptables", "-t", "nat", "-A", chain, "-d", subnet, "-p", "tcp",
                      "--dport", str(proto_port), "-j", "REDIRECT", "--to-ports", str(port))
    for ip in ipv4:
        for proto_port in cfg["ports"]:
            _iptables("iptables", "-t", "nat", "-A", chain, "-d", f"{ip}/32", "-p", "tcp",
                      "--dport", str(proto_port), "-j", "REDIRECT", "--to-ports", str(port))

    _iptables("ip6tables", "-N", chain6)
    _ensure_jump("ip6tables", (), chain6, None)
    _iptables("ip6tables", "-F", chain6)
    for ip in ipv6:
        _iptables("ip6tables", "-A", chain6, "-d", ip, "-p", "tcp", "--dport", "443",
                  "-j", "REJECT", "--reject-with", "tcp-reset")
    return {
        "ipv4_rules": len(ipv4) + len(static_subnets),
        "ipv6_rules": len(ipv6),
        "active_domains": len(active),
        "static_subnets": len(static_subnets),
    }


def chain_rules(cfg: dict):
    result = run(["iptables", "-t", "nat", "-S", cfg["chain"]])
    count = len([line for line in result.stdout.splitlines() if line.startswith("-A ")])
    return count


# --------------------------------------------------------------------------- #
# state and synchronisation
# --------------------------------------------------------------------------- #
def new_entry(domain: str, source: str = "seed") -> dict:
    return {
        "domain": domain,
        "pinned": False,
        "source": source,
        "verdict": None,
        "active": False,
        "direct_streak": 0,
        "checks": 0,
        "ips": [],
        "ips6": [],
        "last_check": None,
        "since": None,
        "last_error": None,
    }


def sync(cfg: dict, state: dict, *, only: Optional[List[str]] = None) -> dict:
    proxy = read_redsocks(cfg)
    entries = state.setdefault("entries", {})
    watch = list(dict.fromkeys([*cfg["watch"], *(only or [])]))
    for domain in watch:
        entries.setdefault(domain, new_entry(domain))

    def work(domain: str) -> Tuple[str, dict]:
        return domain, classify(domain, cfg, proxy)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
        for domain, outcome in pool.map(work, watch):
            results[domain] = outcome

    added, removed = [], []
    for domain, outcome in results.items():
        entry = entries[domain]
        was_active = bool(entry.get("active"))
        entry["verdict"] = outcome["verdict"]
        entry["checks"] = int(entry.get("checks", 0)) + 1
        entry["last_check"] = now_iso()
        entry["last_direct"] = outcome["direct"]
        entry["last_proxy"] = outcome["proxy"]
        if outcome["verdict"] == "blocked":
            entry["reason"] = "geo-block" if _geo_blocked(outcome["direct"]) else "network"
        elif outcome["verdict"] == "direct":
            entry["reason"] = None
        if outcome["ips"]:
            entry["ips"] = outcome["ips"]
        if outcome["ips6"]:
            entry["ips6"] = outcome["ips6"]
        if outcome["verdict"] == "direct":
            entry["direct_streak"] = int(entry.get("direct_streak", 0)) + 1
        else:
            entry["direct_streak"] = 0
        if outcome["verdict"] == "blocked":
            entry["active"] = True
            entry["since"] = entry.get("since") or now_iso()
            if not was_active:
                added.append(domain)
        elif entry.get("pinned"):
            entry["active"] = True
            if not was_active and outcome["verdict"] == "blocked":
                added.append(domain)
        elif entry.get("direct_streak", 0) >= 2:
            entry["active"] = False
            if was_active:
                removed.append(domain)
        elif entry.get("active") and outcome["verdict"] == "unreachable":
            # keep the previous decision while both paths fail: a transient
            # outage must not silently drop an established bypass.
            pass
    stats = apply_rules(cfg, entries, state.get("subnets", []))
    state["updated_at"] = now_iso()
    state["chain"] = cfg["chain"]
    state["last_sync"] = {
        "checked": len(watch),
        "added": added,
        "removed": removed,
        "blocked": [d for d, o in results.items() if o["verdict"] == "blocked"],
        "direct": [d for d, o in results.items() if o["verdict"] == "direct"],
        "unreachable": [d for d, o in results.items() if o["verdict"] == "unreachable"],
        **stats,
    }
    return state["last_sync"]


# --------------------------------------------------------------------------- #
# learning from logs
# --------------------------------------------------------------------------- #
def tail_lines(path: str, limit: int) -> List[str]:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            start = max(0, size - limit * 400)
            handle.seek(start)
            data = handle.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[-limit:]


def extract_domains(lines: List[str], cfg: dict, known: Set[str]) -> Dict[str, str]:
    """Return {domain: evidence line} of plausible blocked-resource host names."""
    ignore = set(cfg.get("ignore", []))
    found: Dict[str, str] = {}
    for line in lines:
        lowered = line.lower()
        if not any(marker in lowered for marker in ERROR_MARKERS):
            continue
        for match in URL_HOST_RE.finditer(line):
            candidate = match.group(1).lower()
            if candidate in known or candidate in ignore or not DOMAIN_RE.match(candidate):
                continue
            found.setdefault(candidate, line.strip()[:240])
        for match in BARE_HOST_RE.finditer(line):
            candidate = match.group(1).lower()
            if candidate in known or candidate in ignore or not DOMAIN_RE.match(candidate):
                continue
            found.setdefault(candidate, line.strip()[:240])
        if len(found) >= cfg["learn"]["max_new"] * 3:
            break
    return found


def learn(cfg: dict, state: dict) -> dict:
    entries = state.setdefault("entries", {})
    known = set(entries)
    candidates: Dict[str, str] = {}
    scanned = []
    for pattern in cfg["learn"].get("globs", []):
        for path in sorted(glob.glob(pattern)):
            if not os.path.isfile(path):
                continue
            scanned.append(path)
            candidates.update(extract_domains(tail_lines(path, int(cfg["learn"]["max_lines"])), cfg, known))
    proxy = read_redsocks(cfg)
    checked = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
        futures = {pool.submit(classify, domain, cfg, proxy): domain for domain in candidates}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                checked.append(future.result())
            except Exception as error:  # noqa: BLE001
                log(f"learn probe failed for {domain}: {error}")
    added = []
    for outcome in sorted(checked, key=lambda item: item["domain"]):
        if outcome["verdict"] != "blocked":
            continue
        domain = outcome["domain"]
        entry = entries.setdefault(domain, new_entry(domain, source="log-learn"))
        entry.update(verdict="blocked", active=True, ips=outcome["ips"], ips6=outcome["ips6"],
                     last_check=now_iso(), last_direct=outcome["direct"], last_proxy=outcome["proxy"],
                     source="log-learn", since=entry.get("since") or now_iso())
        added.append(domain)
        if len(added) >= int(cfg["learn"]["max_new"]):
            break
    stats = apply_rules(cfg, entries, state.get("subnets", []))
    state["updated_at"] = now_iso()
    return {"scanned_files": len(scanned), "candidates": [c["domain"] for c in checked],
            "added": added, **stats}


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def service_state() -> dict:
    out = run(["systemctl", "is-active", "proxy-bypass.service"])
    red = run(["systemctl", "is-active", "redsocks"])
    return {"proxy_bypass": out.stdout.strip() or "unknown", "redsocks": red.stdout.strip() or "unknown"}


def cmd_status(cfg: dict) -> dict:
    state = load_state()
    entries = state.get("entries", {})
    return {
        "ok": True,
        "updated_at": state.get("updated_at"),
        "chain": cfg["chain"],
        "chain_rules": chain_rules(cfg),
        "service": service_state(),
        "last_sync": state.get("last_sync"),
        "entries": [
            {
                "domain": entry["domain"],
                "verdict": entry.get("verdict"),
                "active": bool(entry.get("active")),
                "pinned": bool(entry.get("pinned")),
                "source": entry.get("source"),
                "ips": len(entry.get("ips", [])),
                "last_check": entry.get("last_check"),
            }
            for entry in sorted(entries.values(), key=lambda item: item["domain"])
        ],
    }


def cmd_check(cfg: dict, domain: str) -> dict:
    proxy = read_redsocks(cfg)
    # An honest "direct" measurement needs our SO_MARK rule to exist; this adds
    # only that service rule (a RETURN for marked packets), never a redirect.
    mark_changes = ensure_mark_bypass()
    result = classify(valid_domain(domain), cfg, proxy)
    return {"ok": True, **result, "mark_bypass_changes": mark_changes}


def cmd_add(cfg: dict, state: dict, domain: str, *, pin: bool) -> dict:
    domain = valid_domain(domain)
    if domain not in cfg["watch"]:
        cfg["watch"].append(domain)
        save_config(cfg)
    entry = state.setdefault("entries", {}).setdefault(domain, new_entry(domain, source="manual"))
    if pin:
        entry["pinned"] = True
        entry["source"] = "manual"
    stats = sync(cfg, state, only=[domain])
    save_state(state)
    return {"ok": True, "domain": domain, "pinned": bool(entry.get("pinned")),
            "verdict": entry.get("verdict"), "active": bool(entry.get("active")), **stats}


def cmd_remove(cfg: dict, state: dict, domain: str) -> dict:
    domain = valid_domain(domain)
    cfg["watch"] = [item for item in cfg["watch"] if item != domain]
    save_config(cfg)
    entry = state.setdefault("entries", {}).pop(domain, None)
    stats = apply_rules(cfg, state.get("entries", {}), state.get("subnets", []))
    state["updated_at"] = now_iso()
    save_state(state)
    return {"ok": True, "domain": domain, "removed": entry is not None, **stats}


def _valid_subnet(value: str) -> str:
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as error:
        raise ValueError(f"not a valid IPv4 subnet: {value!r}") from error
    if network.version != 4:
        raise ValueError("only IPv4 subnets are supported")
    return str(network)


def cmd_add_ip(cfg: dict, state: dict, cidr: str) -> dict:
    """Route a whole IPv4 subnet through the proxy, independent of DNS."""
    subnet = _valid_subnet(cidr)
    subnets = state.setdefault("subnets", [])
    if subnet not in subnets:
        subnets.append(subnet)
    stats = apply_rules(cfg, state.get("entries", {}), subnets)
    state["updated_at"] = now_iso()
    save_state(state)
    return {"ok": True, "cidr": subnet, "subnets": subnets, **stats}


def cmd_remove_ip(cfg: dict, state: dict, cidr: str) -> dict:
    subnet = _valid_subnet(cidr)
    subnets = state.setdefault("subnets", [])
    removed = subnet in subnets
    state["subnets"] = [item for item in subnets if item != subnet]
    stats = apply_rules(cfg, state.get("entries", {}), state["subnets"])
    state["updated_at"] = now_iso()
    save_state(state)
    return {"ok": True, "cidr": subnet, "removed": removed, **stats}


def cmd_sync(cfg: dict) -> dict:
    state = load_state()
    stats = sync(cfg, state)
    save_state(state)
    return {"ok": True, **stats}


def cmd_learn(cfg: dict) -> dict:
    state = load_state()
    stats = learn(cfg, state)
    save_state(state)
    return {"ok": True, **stats}


def cmd_daemon(cfg: dict) -> None:
    save_config(cfg)  # normalised defaults become visible for humans
    state = load_state()
    interval = max(1, int(cfg["interval_min"])) * 60
    learn_every = max(1, int(cfg["learn_every"]))
    cycle = 0
    log(f"daemon started: chain={cfg['chain']} interval={interval}s learn_every={learn_every}")
    while True:
        try:
            stats = sync(cfg, state)
            log(f"sync: checked={stats['checked']} blocked={len(stats['blocked'])} "
                f"active={stats['active_domains']} rules={stats['ipv4_rules']}")
            if cfg["learn"].get("enabled") and cycle % learn_every == 0:
                learned = learn(cfg, state)
                log(f"learn: files={learned['scanned_files']} new={learned['added']}")
            save_state(state)
        except Exception as error:  # noqa: BLE001 - the daemon must survive a bad cycle
            log(f"cycle failed: {type(error).__name__}: {error}")
            save_state(state)
        cycle += 1
        time.sleep(interval)


def save_config(cfg: dict) -> None:
    write_json_atomic(CONFIG_PATH, cfg, mode=0o600)


def save_state(state: dict) -> None:
    write_json_atomic(STATE_PATH, state, mode=0o600)


def load_state() -> dict:
    state = read_json(STATE_PATH, {})
    if not isinstance(state, dict):
        state = {}
    state.setdefault("entries", {})
    state.setdefault("subnets", [])
    return state


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="proxy-bypass", description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["status", "sync", "check", "add", "remove", "learn",
                                            "add-ip", "remove-ip", "daemon"])
    parser.add_argument("--domain")
    parser.add_argument("--cidr", help="IPv4 subnet to route through the proxy, e.g. 203.0.113.0/24")
    parser.add_argument("--pin", action="store_true", help="never auto-remove this domain")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    cfg = load_config()

    if args.command == "status":
        result = cmd_status(cfg)
    elif args.command == "sync":
        result = cmd_sync(cfg)
    elif args.command == "learn":
        result = cmd_learn(cfg)
    elif args.command == "check":
        if not args.domain:
            parser.error("--domain is required")
        result = cmd_check(cfg, args.domain)
    elif args.command == "add":
        if not args.domain:
            parser.error("--domain is required")
        result = cmd_add(cfg, load_state(), args.domain, pin=args.pin)
    elif args.command == "remove":
        if not args.domain:
            parser.error("--domain is required")
        result = cmd_remove(cfg, load_state(), args.domain)
    elif args.command == "add-ip":
        if not args.cidr:
            parser.error("--cidr is required")
        result = cmd_add_ip(cfg, load_state(), args.cidr)
    elif args.command == "remove-ip":
        if not args.cidr:
            parser.error("--cidr is required")
        result = cmd_remove_ip(cfg, load_state(), args.cidr)
    else:  # daemon
        lock_handle = open(LOCK_PATH, "w")  # noqa: SIM115 - held for the process lifetime
        try:
            if fcntl is not None:
                fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("another proxy-bypass daemon holds the lock")
            return 1
        cmd_daemon(cfg)
        return 0

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(_human(result))
    return 0 if result.get("ok") else 2


def _human(result: dict) -> str:
    if "entries" in result:
        lines = [f"chain={result['chain']} rules={result['chain_rules']} "
                 f"service={result['service']['proxy_bypass']} redsocks={result['service']['redsocks']}"]
        for entry in result["entries"]:
            flag = "proxied" if entry["active"] else "-"
            lines.append(f"  {entry['domain']:<40} {str(entry['verdict']):<12} {flag:<8} "
                         f"ips={entry['ips']:<2} {entry['source']}")
        return "\n".join(lines)
    return json.dumps(result, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    sys.exit(main())
