# RepoHush

I made RepoHush to catch a few easy-to-miss mistakes before running a coding agent in a repo.

It checks for things like committed `.env` files, private keys, tokens, disabled sandboxes and suspicious commands in MCP configs. Everything happens locally. There is no account, server or telemetry.

```bash
npx repohush scan .
```

Node 20 or newer is required. A high or critical finding makes the command exit with code `1`, so the same command works in CI.

```text
RepoHush
Scanned 42 files in 18.4ms

CRITICAL RH203 .mcp.json:4
         Configuration downloads and directly executes a remote script.
HIGH     RH001 .env:1
         Environment file may expose credentials to source control or coding agents.
```

JSON and SARIF output are available when plain terminal output is not enough:

```bash
repohush scan . --format json
repohush scan . --format sarif --output repohush.sarif
repohush scan . --fail-on critical
```

Use `.repohushignore` for fake credentials in test fixtures or generated examples:

```gitignore
test/fixtures/**
docs/generated/**
```

Do not add a real leak to this file just to get a green build. Revoke the key and remove it from Git history.

## GitHub Action

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: synoxreal/repohush@v0
    with:
      fail-on: high
```

## Current limits

This is a small pattern-based scanner, not a security audit. It can miss unusual key formats and it can report fake values as real ones. It skips symlinks, binaries, generated folders and files larger than 1 MiB.

If you find a noisy rule, open an issue with a fake example. Please do not paste the actual key.

## Working on it

```bash
npm install
npm run check
node dist/cli.js scan . --no-fail
```

MIT License
