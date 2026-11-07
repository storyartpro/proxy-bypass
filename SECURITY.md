# Security policy

## Scope

Proxy Bypass runs locally on a Windows workstation and manages Linux servers over SSH. The most
sensitive assets are:

- proxy credentials in `data/config.json` (plain text, local file);
- SSH keys used to reach the servers;
- the server-side `redsocks` configuration with the same proxy credentials.

## Design decisions

- The UI and the routing proxy listen on `127.0.0.1` only; there is no network-facing service.
- `data/` is excluded from the repository and should never be published.
- Server credentials are passed over SSH stdin, never as command-line arguments, so they do not
  appear in process lists or shell history.
- Pushing a proxy to a server writes `/etc/redsocks.conf.bak.<timestamp>` before modifying it.
- The Windows system proxy is snapshotted before enabling and restored when disabling.

## Known limitations

- Proxy credentials are stored unencrypted on the workstation. Protect the Windows account and
  disk (BitLocker) until DPAPI encryption lands.
- Anyone with local user access can read `data/config.json` and the server list.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability
reporting on the repository ("Security" → "Report a vulnerability") or contact the maintainer
directly. Include:

- affected version/commit;
- steps to reproduce;
- impact assessment;
- suggested fix, if you have one.

Expect an initial response within a few days. Please give reasonable time to ship a fix before
public disclosure.
