# Plasmatix Agent

Local edge agent for ZKTeco scanners, ZKBio CVAccess, and ZKBioTime. It
connects back to Plasmatix and keeps official-system credentials on the local
network.

## Features

- Reverse SSE connection (agent initiates outbound, no inbound ports needed)
- ZKBio session caching with auto-relogin
- Remote commands: employee sync, attendance transactions, daily/monthly reports
- Self-update and self-uninstall via remote commands
- Systemd service integration
- Adaptive TA PUSH 2.x / AC PUSH 3.x protocol detection
- Profile-aware fingerprint enrollment, write, and delete commands
- Durable JPEG/PNG scanner photo forwarding
- Read-only ZKBioTime PostgreSQL migration preflight and extraction

## Installation

The agent is installed via a generated script from the Plasmatix web UI. Go to **Settings > Agent**, configure your ZKBio connection, then copy the install command.

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

The mock device handshakes and polls `/iclock/getrequest`. AC PUSH fixtures
upload synthetic BioData records; TA PUSH fixtures expect `ENROLL_FP` and
upload FINGERTMP metadata. Override defaults with env vars or flags:

```bash
AGENT_URL=http://127.0.0.1:8081 DEVICE_SN=NYU0000000001 make mock
# or:
go run ./scripts/dev/mock-device --agent http://127.0.0.1:8081 --sn NYU0000000001 --profile ta_push --poll 1s
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
  "zkbio_password": "...",
  "migration_dsn": "postgres://readonly_user:...@127.0.0.1:5432/zkbiotime?sslmode=disable"
}
```

`migration_dsn` is optional. Store it only in the Agent configuration and use
a PostgreSQL role that cannot write. Migration commands run in a repeatable,
read-only transaction and use fixed allowlisted queries. CVAccess database
migration remains disabled until its database engine and schema are validated;
the CVAccess REST integration continues to work.

## Commands

| Command | Description |
|---------|-------------|
| `health` | Returns status, version, uptime |
| `info` | Returns full system info (hostname, OS, memory, etc.) |
| `fetchEmployees` | Fetches employee list from ZKBio |
| `fetchTransactions` | Fetches attendance punch records |
| `fetchDailyReport` | Fetches daily attendance report |
| `fetchMonthlyReport` | Fetches monthly attendance report |
| `migration_preflight` | Verifies the local ZKBioTime database and returns a source fingerprint |
| `migration_inventory` | Returns read-only source entity counts |
| `migration_read_batch` | Reads one allowlisted, cursor-based source batch |
| `update` | Downloads new binary, replaces itself, restarts |
| `uninstall` | Stops service, removes all files, exits |
