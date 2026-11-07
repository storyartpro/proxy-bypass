# Contributing

Thanks for taking a look at Proxy Bypass. The project is small and stays dependency-free on
purpose: Node.js built-ins only, no build step, no bundler.

## Development

```cmd
git clone https://github.com/storyartpro/proxy-bypass.git
cd proxy-bypass
node --version        # must be 20+
start.cmd             # runs app/server.mjs and opens the window
npm test              # unit tests (node --test)
```

- The UI is plain HTML/CSS/JS in `app/ui/`; edit and reload the window.
- The backend is ES modules in `app/`; restart the app after changes.
- Settings for a local run live in `data/config.json` (git-ignored). Never commit that directory.

## Rules

1. **No secrets, ever.** `data/`, credentials, server addresses and personal paths stay out of
   commits. Check `git diff --cached` before pushing.
2. Node.js built-ins only. A new dependency needs a strong reason in the pull request.
3. Keep the two planes separate: the workstation must not route user traffic through managed
   servers; SSH is a control channel only.
4. Never let a socket error become an uncaught exception — the app runs inside its own process and
   must keep serving. Attach error handlers to every socket, timer and promise chain you add.
5. Update `CHANGELOG.md` under `## [Unreleased]` for user-visible changes.
6. Russian and English UI strings should stay in sync where the UI is localised.

## Tests

`npm test` runs `node --test test/`. Tests must not touch the network, the registry or real
servers: use a fake SOCKS5 server in-process for protocol work.

## Pull requests

- One logical change per pull request, described in the imperative mood.
- Include a short "how I verified" section (commands and observed results).
- Screenshots are welcome for UI changes; mask personal data first.

## Commit style

```
feat: add per-server proxy selection
fix: keep the window reopen working when the app is already running
docs: describe the failover probe
```

## License

By contributing you agree that your work is published under the MIT license.
