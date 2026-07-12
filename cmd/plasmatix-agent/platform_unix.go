//go:build !windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Filesystem layout on Linux/macOS hosts, matching what the bash installer
// (generateInstallScript in the Plasmatix web app) lays down.
const (
	defaultConfigPath = "/etc/plasmatix/agent.yaml"
	agentConfigPath   = "/etc/plasmatix/agent.json"
	agentBinPath      = "/usr/local/bin/plasmatix-agent"
	serviceName       = "plasmatix-agent"
)

// runAgent runs the agent in the foreground. systemd supervises us as a
// Type=simple unit, so there is no service protocol to speak here.
func runAgent(run func()) {
	run()
}

// cleanupAfterUpdate is a no-op on unix: os.Rename replaces a running binary
// in place, so a self-update leaves nothing behind.
func cleanupAfterUpdate() {}

// collectPlatformInfo adds OS-specific host facts to the systemInfo payload.
func collectPlatformInfo(info map[string]any) {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info["osRelease"] = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		mem := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if key == "MemTotal" || key == "MemAvailable" {
					mem[key] = val
				}
			}
		}
		info["memTotal"] = mem["MemTotal"]
		info["memAvailable"] = mem["MemAvailable"]
	}
}

// serviceStatus reports what the init system thinks of us ("active", "failed", …).
func serviceStatus() (string, bool) {
	out, err := exec.Command("systemctl", "is-active", serviceName).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// installUpdate swaps the freshly downloaded binary over the running one.
// On unix a running executable is an open inode, so a plain rename is atomic
// and safe — the old inode stays alive until we exit.
func installUpdate(tmpPath, binPath string) error {
	if err := os.Rename(tmpPath, binPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}

// restartService asks systemd to restart us. If that fails we exit non-zero and
// rely on Restart=always to bring us back on the new binary.
func restartService() {
	time.Sleep(time.Second)
	log.Println("Restarting service...")
	cmd := exec.Command("systemctl", "restart", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("restart failed: %v — exiting to let systemd restart us", err)
		os.Exit(1)
	}
}

// launchUninstaller writes a detached cleanup script and hands off to it.
// Cleanup can't run inline: `systemctl stop` SIGTERMs us mid-script.
func launchUninstaller() error {
	script := `#!/bin/bash
sleep 2
systemctl stop ` + serviceName + ` 2>/dev/null
systemctl disable ` + serviceName + ` 2>/dev/null
rm -f /etc/systemd/system/` + serviceName + `.service
systemctl daemon-reload 2>/dev/null
rm -rf /etc/plasmatix
rm -f ` + agentBinPath + `
rm -f /tmp/plasmatix-uninstall.sh
`
	scriptPath := "/tmp/plasmatix-uninstall.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("write script: %w", err)
	}

	cmd := exec.Command("bash", scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start script: %w", err)
	}
	return nil
}
