.PHONY: build dev mock test lint clean release-darwin release-linux

# Local dev config & state. Both gitignored.
CONFIG := scripts/dev/agent.local.json
STATE_DIR := .dev

VERSION := $(shell cat VERSION)
LDFLAGS := -X main.version=$(VERSION)

# Native build for macOS (Apple Silicon). Run `make` and you get a binary
# you can invoke directly without leaving the repo.
build:
	@mkdir -p $(STATE_DIR)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(STATE_DIR)/plasmatix-agent ./cmd/plasmatix-agent
	@echo "→ $(STATE_DIR)/plasmatix-agent ($(VERSION))"

# Build then run with the local config. Ctrl-C to stop. Run again after a
# code change — there's no daemon, just rebuild + relaunch.
#
# First run: `cp scripts/dev/agent.example.json $(CONFIG)` and fill in
# api_key + plasmatix_url for whichever org/backend you want to talk to.
dev: build
	@if [ ! -f $(CONFIG) ]; then \
		echo "missing $(CONFIG) — copy scripts/dev/agent.example.json and fill it in"; \
		exit 1; \
	fi
	$(STATE_DIR)/plasmatix-agent --config $(CONFIG)

# Run the mock device emulator against a locally-running agent. Use this
# when you can't point a real device at your Mac (different LAN, no device
# on hand, etc.). It handshakes, polls /iclock/getrequest, and when it
# receives ENROLL_BIO it uploads a synthetic BioData record so you can
# exercise the reflection path end-to-end.
#
# Override defaults with env vars: AGENT_URL, DEVICE_SN, POLL_INTERVAL.
mock:
	go run ./scripts/dev/mock-device

lint:
	go vet ./...

test:
	go test ./...

# Cross-compile binaries the way the deploy scripts expect (linux/amd64).
release-linux:
	@mkdir -p $(STATE_DIR)
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w $(LDFLAGS)" \
		-o $(STATE_DIR)/plasmatix-agent.linux-amd64 ./cmd/plasmatix-agent
	@echo "→ $(STATE_DIR)/plasmatix-agent.linux-amd64 ($(VERSION))"

release-darwin:
	@mkdir -p $(STATE_DIR)
	go build -trimpath -ldflags="-s -w $(LDFLAGS)" \
		-o $(STATE_DIR)/plasmatix-agent.darwin-arm64 ./cmd/plasmatix-agent
	@echo "→ $(STATE_DIR)/plasmatix-agent.darwin-arm64 ($(VERSION))"

clean:
	rm -rf $(STATE_DIR)
