# Plasmatix Agent

Standalone agent that runs on machines with access to ZKBio CVAccess. Connects back to Plasmatix via SSE (Server-Sent Events) to receive commands.

## Features

- Reverse SSE connection (agent initiates outbound, no inbound ports needed)
- ZKBio session caching with auto-relogin
- Durable ZKBioTime sync checkpoints, so an Agent restart resumes from Plasmatix's last acknowledged batch
- Remote commands: employee sync, attendance transactions, daily/monthly reports
- Self-update and self-uninstall via remote commands
- Runs as a native service: systemd on Linux, Service Control Manager on Windows

## Supported platforms

| Platform | Service | Layout |
| --- | --- | --- |
| Linux (amd64/arm64) | systemd unit `plasmatix-agent` | bin `/usr/local/bin/plasmatix-agent`, config `/etc/plasmatix/agent.json` |
| Windows (amd64/arm64) | SCM service `PlasmatixAgent` | bin `%ProgramFiles%\Plasmatix\plasmatix-agent.exe`, config `%ProgramData%\Plasmatix\agent.json` |
| macOS (amd64/arm64) | none — binary only, run in the foreground | — |

Windows supports the `zkbio` and `zkbiotime` modes. ADMS mode is Linux-only: it
needs an inbound listener, which the Windows installer deliberately does not
open a firewall rule for.

Platform-specific behavior (paths, service control, self-update, uninstall) is
isolated in `platform_unix.go` / `platform_windows.go` behind one small
interface — `main.go` stays OS-agnostic.

## Installation

The agent is installed via a generated script from the Plasmatix web UI. Go to **Settings > Agent**, configure your ZKBio connection, then copy the install command (bash for Linux, PowerShell for Windows).

## Manual build

```bash
go build -trimpath -ldflags="-s -w -X main.version=$(cat VERSION)" -o plasmatix-agent ./cmd/plasmatix-agent
```

## Local development (no remote deploy needed)

The `Makefile` builds and runs the agent natively on macOS so you can iterate
on `cmd/plasmatix-agent` without scping a binary anywhere.

```bash
# 1. One-time: copy the example config and fill in api_key + plasmatix_url.
cp scripts/dev/agent.example.json scripts/dev/agent.local.json
$EDITOR scripts/dev/agent.local.json

# 2. Build + run with that config.
make dev

# 3. In another terminal, drive a fake ZKBio device against the local agent.
#    Useful when no real device is on the same LAN as your Mac.
make mock
```

Code change → Ctrl-C → `make dev` again. Build is ~2s native.

The mock device handshakes, polls `/iclock/getrequest`, and when the agent
serves an `ENROLL_BIO` it uploads a synthetic BioData record so the
reflection path runs. Override defaults with env vars or flags:

```bash
AGENT_URL=http://127.0.0.1:8081 DEVICE_SN=NYU0000000001 make mock
# or:
go run ./scripts/dev/mock-device --agent http://127.0.0.1:8081 --sn NYU0000000001 --poll 1s
```

Other useful targets: `make build` (just compile), `make lint` (`go vet`),
`make release-linux` / `make release-darwin` (cross-compile a deploy
binary into `.dev/`), `make clean`.

`scripts/dev/agent.local.json` and `.dev/` are gitignored.

## Release

1. Bump the version in `VERSION`
2. Push to `main`
3. GitHub Actions automatically tags and creates a release with binaries

## Configuration

The agent reads its config from `/etc/plasmatix/agent.json`:

```json
{
  "api_key": "...",
  "plasmatix_url": "https://...",
  "zkbio_url": "https://192.168.1.10:8098",
  "zkbio_username": "admin",
  "zkbio_password": "..."
}
```

## Commands

| Command | Description |
|---------|-------------|
| `health` | Returns status, version, uptime |
| `info` | Returns full system info (hostname, OS, memory, etc.) |
| `fetchEmployees` | Fetches employee list from ZKBio |
| `fetchTransactions` | Fetches attendance punch records |
| `fetchDailyReport` | Fetches daily attendance report |
| `fetchMonthlyReport` | Fetches monthly attendance report |
| `update` | Downloads new binary, replaces itself, restarts |
| `uninstall` | Stops service, removes all files, exits |
