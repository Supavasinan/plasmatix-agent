//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Filesystem layout on Windows hosts, matching what the PowerShell installer
// (generateWindowsInstallScript in the Plasmatix web app) lays down. Unlike the
// unix paths these are computed, because ProgramFiles/ProgramData are not
// guaranteed to sit on C: (localized or redirected installs move them).
const serviceName = "PlasmatixAgent"

var (
	installDir = filepath.Join(envOr("ProgramFiles", `C:\Program Files`), "Plasmatix")
	configDir  = filepath.Join(envOr("ProgramData", `C:\ProgramData`), "Plasmatix")

	agentBinPath      = filepath.Join(installDir, "plasmatix-agent.exe")
	agentConfigPath   = filepath.Join(configDir, "agent.json")
	defaultConfigPath = agentConfigPath
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// x/sys/windows has no binding for GlobalMemoryStatusEx, so bind it ourselves.
// Field order and widths must match the Win32 MEMORYSTATUSEX struct exactly.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

func globalMemoryStatus() (memoryStatusEx, error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	// Win32 signals failure with a zero return; err is only meaningful then.
	if r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return m, err
	}
	return m, nil
}

// windowsService adapts the agent's blocking run loop to the Service Control
// Manager's protocol. Without this the SCM kills the process after ~30s for
// failing to report SERVICE_RUNNING.
type windowsService struct {
	run func()
}

func (s *windowsService) Execute(
	_ []string,
	r <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case <-done:
			// The agent's run loop returned on its own — an unexpected exit.
			// Report a non-zero code so the SCM's configured failure action
			// (restart/5000) brings us back, mirroring systemd's Restart=always.
			changes <- svc.Status{State: svc.StopPending}
			return false, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			default:
				log.Printf("service: unexpected control request #%d", c.Cmd)
			}
		}
	}
}

// runAgent runs under the SCM when launched as a service, and in the foreground
// when a human runs the .exe from a console (useful for debugging an install).
func runAgent(run func()) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("service: cannot determine session type (%v) — running in console mode", err)
		run()
		return
	}
	if !isService {
		log.Println("Running in console mode (not started by the Service Control Manager)")
		run()
		return
	}

	if err := svc.Run(serviceName, &windowsService{run: run}); err != nil {
		log.Fatalf("service: run %s: %v", serviceName, err)
	}
}

// cleanupAfterUpdate removes the previous binary parked by installUpdate.
// Windows won't let us delete a running .exe, so the swap leaves a .old behind
// that only the *next* process (this one) can clear.
func cleanupAfterUpdate() {
	old := agentBinPath + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		log.Printf("cleanup: could not remove %s: %v", old, err)
	}
}

// collectPlatformInfo adds OS-specific host facts to the systemInfo payload.
func collectPlatformInfo(info map[string]any) {
	v := windows.RtlGetVersion()
	info["osRelease"] = fmt.Sprintf("Windows %d.%d (build %d)",
		v.MajorVersion, v.MinorVersion, v.BuildNumber)

	if mem, err := globalMemoryStatus(); err == nil {
		// Reported in kB with a trailing unit so the UI renders these the same
		// way it renders Linux's /proc/meminfo values.
		info["memTotal"] = fmt.Sprintf("%d kB", mem.TotalPhys/1024)
		info["memAvailable"] = fmt.Sprintf("%d kB", mem.AvailPhys/1024)
	}
}

// serviceStatus reports what the SCM thinks of us, normalized to the same
// vocabulary systemd uses so the Plasmatix UI needs no per-OS branch.
func serviceStatus() (string, bool) {
	m, err := mgr.Connect()
	if err != nil {
		return "", false
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return "", false
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", false
	}

	switch status.State {
	case svc.Running:
		return "active", true
	case svc.StartPending:
		return "activating", true
	case svc.StopPending:
		return "deactivating", true
	case svc.Stopped:
		return "inactive", true
	default:
		return "unknown", true
	}
}

// installUpdate swaps the freshly downloaded binary over the running one.
// Windows holds an exclusive lock on a running image, so a rename *onto* the
// binary fails with ERROR_ACCESS_DENIED. Renaming the running image away is
// allowed though, so: move ourselves aside, then move the new binary in.
func installUpdate(tmpPath, binPath string) error {
	old := binPath + ".old"

	// A .old can survive a crash between the two renames below; clear it first
	// or the rename-aside fails and self-update wedges permanently.
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear previous backup %s: %w", old, err)
	}

	if err := os.Rename(binPath, old); err != nil {
		return fmt.Errorf("move running binary aside: %w", err)
	}

	if err := os.Rename(tmpPath, binPath); err != nil {
		// Put the running binary back, otherwise the service has no image to
		// restart from and the host is left without an agent.
		if rbErr := os.Rename(old, binPath); rbErr != nil {
			return fmt.Errorf("replace binary: %w (rollback also failed: %v)", err, rbErr)
		}
		return fmt.Errorf("replace binary: %w", err)
	}

	return nil
}

// restartService bounces the service via a detached helper. We cannot stop and
// start ourselves inline: `sc stop` terminates this very process, so the second
// half of the command would never run. The helper outlives us.
func restartService() {
	time.Sleep(time.Second)
	log.Println("Restarting service...")

	script := "@echo off\r\n" +
		"timeout /t 2 /nobreak >nul\r\n" +
		"sc stop " + serviceName + " >nul 2>&1\r\n" +
		"timeout /t 3 /nobreak >nul\r\n" +
		"sc start " + serviceName + " >nul 2>&1\r\n" +
		`del "%~f0"` + "\r\n"

	scriptPath := filepath.Join(os.TempDir(), "plasmatix-restart.cmd")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		log.Printf("restart: write script: %v — exiting to let the SCM restart us", err)
		os.Exit(1)
	}

	if err := startDetached("cmd", "/C", scriptPath); err != nil {
		log.Printf("restart failed: %v — exiting to let the SCM restart us", err)
		os.Exit(1)
	}
}

// launchUninstaller writes a detached cleanup script and hands off to it, for
// the same reason as restartService: the script stops the service that spawned it.
func launchUninstaller() error {
	script := "$ErrorActionPreference = 'SilentlyContinue'\r\n" +
		"Start-Sleep -Seconds 3\r\n" +
		"sc.exe stop " + serviceName + "\r\n" +
		"Start-Sleep -Seconds 3\r\n" +
		"sc.exe delete " + serviceName + "\r\n" +
		"Remove-Item -LiteralPath " + psQuote(configDir) + " -Recurse -Force\r\n" +
		"Remove-Item -LiteralPath " + psQuote(installDir) + " -Recurse -Force\r\n" +
		"Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force\r\n"

	scriptPath := filepath.Join(os.TempDir(), "plasmatix-uninstall.ps1")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("write script: %w", err)
	}

	if err := startDetached(
		"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath,
	); err != nil {
		return fmt.Errorf("start script: %w", err)
	}
	return nil
}

// startDetached launches a child that survives this process being terminated by
// the SCM — the Windows counterpart of Setsid on unix.
func startDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}

// psQuote renders a path as a PowerShell single-quoted literal, where the only
// escape is a doubled quote.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
