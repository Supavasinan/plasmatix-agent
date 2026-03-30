# Plasmatix Agent

Standalone agent that runs on machines with access to ZKBio CVAccess. Connects back to Plasmatix via SSE (Server-Sent Events) to receive commands.

## Features

- Reverse SSE connection (agent initiates outbound, no inbound ports needed)
- ZKBio session caching with auto-relogin
- Remote commands: employee sync, attendance transactions, daily/monthly reports
- Self-update and self-uninstall via remote commands
- Systemd service integration

## Installation

The agent is installed via a generated script from the Plasmatix web UI. Go to **Settings > Agent**, configure your ZKBio connection, then copy the install command.

## Manual build

```bash
go build -trimpath -ldflags="-s -w -X main.version=$(cat VERSION)" -o plasmatix-agent ./cmd/plasmatix-agent
```

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
