package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

const sessionTTL = 10 * time.Minute

type Config struct {
	APIKey        string
	PlamatixURL   string
	ZKBioURL      string
	ZKBioUsername  string
	ZKBioPassword  string
	Port          int
	Mode          string
	ADMSPort      int
}

type Agent struct {
	config    Config
	startedAt time.Time
	sessions  *SessionManager
}

type loginResponse struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
}

type gridRow struct {
	ID   string `json:"id"`
	Data []any  `json:"data"`
}

type gridResponse struct {
	TotalCount int       `json:"total_count"`
	Pos        int       `json:"pos"`
	Total      int       `json:"total"`
	Rows       []gridRow `json:"rows"`
}

type ZKBioEmployee struct {
	ID             string `json:"id"`
	PersonnelID    string `json:"personnelId"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	DepartmentName string `json:"departmentName"`
	CardNumber     string `json:"cardNumber"`
	Gender         string `json:"gender"`
	HireDate       string `json:"hireDate"`
	Birthday       string `json:"birthday"`
	Photo          string `json:"photo"`
	CreateTime     string `json:"createTime"`
}

type ZKBioEmployeeDetail struct {
	Gender   string
	HireDate string
	Birthday string
	Photo    string
}

type ZKBioTransaction struct {
	ID          string `json:"id"`
	PersonnelID string `json:"personnelId"`
	Name        string `json:"name"`
	Department  string `json:"department"`
	PunchTime   string `json:"punchTime"`
	DeviceName  string `json:"deviceName"`
	Status      string `json:"status"`
	VerifyMode  string `json:"verifyMode"`
}

type ZKBioDailyReport struct {
	ID                 string `json:"id"`
	PersonnelID        string `json:"personnelId"`
	Name               string `json:"name"`
	Department         string `json:"department"`
	Date               string `json:"date"`
	Week               string `json:"week"`
	TimetableName      string `json:"timetableName"`
	WorkTime           string `json:"workTime"`
	PunchData          string `json:"punchData"`
	PunchCounts        string `json:"punchCounts"`
	ShouldMinutes      string `json:"shouldMinutes"`
	ActualMinutes      string `json:"actualMinutes"`
	ValidMinutes       string `json:"validMinutes"`
	LateCounts         string `json:"lateCounts"`
	LateDuration       string `json:"lateDuration"`
	LateTotal          string `json:"lateTotal"`
	EarlyCounts        string `json:"earlyCounts"`
	EarlyDuration      string `json:"earlyDuration"`
	EarlyTotal         string `json:"earlyTotal"`
	OvertimeWeekday    string `json:"overtimeWeekday"`
	OvertimeWeekend    string `json:"overtimeWeekend"`
	OvertimeHoliday    string `json:"overtimeHoliday"`
	OvertimeTotal      string `json:"overtimeTotal"`
	AbsentHours        string `json:"absentHours"`
	PersonalLeave      string `json:"personalLeave"`
	AnnualLeave        string `json:"annualLeave"`
	SickLeave          string `json:"sickLeave"`
	MarriageLeave      string `json:"marriageLeave"`
	MaternityLeave     string `json:"maternityLeave"`
	BreastfeedingLeave string `json:"breastfeedingLeave"`
	HomeLeave          string `json:"homeLeave"`
	BereavementLeave   string `json:"bereavementLeave"`
	BusinessTrip       string `json:"businessTrip"`
	OutHours           string `json:"outHours"`
}

type ZKBioMonthlyReport struct {
	ID             string `json:"id"`
	PersonnelID    string `json:"personnelId"`
	Name           string `json:"name"`
	Department     string `json:"department"`
	TotalDays      string `json:"totalDays"`
	PresentDays    string `json:"presentDays"`
	AbsentDays     string `json:"absentDays"`
	LateDays       string `json:"lateDays"`
	EarlyLeaveDays string `json:"earlyLeaveDays"`
	OvertimeHours  string `json:"overtimeHours"`
}

type ZKBioClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	cookie     string
}

type SessionManager struct {
	config   Config
	ttl      time.Duration
	mu       sync.Mutex
	client   *ZKBioClient
	loginAt  time.Time
	loginCh  chan struct{}
	loginErr error
}

func main() {
	configPath := flag.String("config", "/etc/plasmatix/agent.yaml", "Path to agent config")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	agent := &Agent{
		config:    cfg,
		startedAt: time.Now(),
	}
	if cfg.Mode == "zkbio" {
		agent.sessions = &SessionManager{
			config: cfg,
			ttl:    sessionTTL,
		}
	}

	log.Printf("plasmatix-agent %s starting (mode: %s)", version, cfg.Mode)

	if cfg.Mode == "adms" {
		go agent.startADMSServer()
	}

	agent.connectLoop()
}

func loadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	type jsonConfig struct {
		APIKey        string `json:"api_key"`
		PlamatixURL   string `json:"plasmatix_url"`
		ZKBioURL      string `json:"zkbio_url"`
		ZKBioUsername string `json:"zkbio_username"`
		ZKBioPassword string `json:"zkbio_password"`
		Port          int    `json:"port"`
		Mode          string `json:"mode"`
		ADMSPort      int    `json:"adms_port"`
	}

	var jc jsonConfig
	if json.Unmarshal(raw, &jc) == nil && jc.APIKey != "" {
		return normalizeConfig(Config{
			APIKey:        jc.APIKey,
			PlamatixURL:   jc.PlamatixURL,
			ZKBioURL:      jc.ZKBioURL,
			ZKBioUsername:  jc.ZKBioUsername,
			ZKBioPassword:  jc.ZKBioPassword,
			Port:          jc.Port,
			Mode:          jc.Mode,
			ADMSPort:      jc.ADMSPort,
		})
	}

	parsed := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)
		parsed[key] = value
	}

	port := 9800
	if parsed["port"] != "" {
		parsedPort, err := strconv.Atoi(parsed["port"])
		if err != nil {
			return Config{}, fmt.Errorf("invalid port: %w", err)
		}
		port = parsedPort
	}

	admsPort := 0
	if parsed["adms_port"] != "" {
		parsedADMSPort, err := strconv.Atoi(parsed["adms_port"])
		if err != nil {
			return Config{}, fmt.Errorf("invalid adms_port: %w", err)
		}
		admsPort = parsedADMSPort
	}

	return normalizeConfig(Config{
		APIKey:        parsed["api_key"],
		PlamatixURL:   parsed["plasmatix_url"],
		ZKBioURL:      parsed["zkbio_url"],
		ZKBioUsername: parsed["zkbio_username"],
		ZKBioPassword: parsed["zkbio_password"],
		Port:          port,
		Mode:          parsed["mode"],
		ADMSPort:      admsPort,
	})
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	cfg.PlamatixURL = strings.TrimRight(strings.TrimSpace(cfg.PlamatixURL), "/")
	cfg.ZKBioURL = strings.TrimRight(strings.TrimSpace(cfg.ZKBioURL), "/")
	cfg.ZKBioUsername = strings.TrimSpace(cfg.ZKBioUsername)
	cfg.ZKBioPassword = strings.TrimSpace(cfg.ZKBioPassword)
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Port == 0 {
		cfg.Port = 9800
	}
	if cfg.Mode == "" {
		cfg.Mode = "zkbio"
	}
	if cfg.ADMSPort == 0 {
		cfg.ADMSPort = 8081
	}

	if cfg.Mode != "zkbio" && cfg.Mode != "adms" {
		return Config{}, fmt.Errorf("invalid mode %q: must be \"zkbio\" or \"adms\"", cfg.Mode)
	}

	switch {
	case cfg.APIKey == "":
		return Config{}, errors.New("missing api_key")
	case cfg.PlamatixURL == "":
		return Config{}, errors.New("missing plasmatix_url")
	}

	if cfg.Mode == "zkbio" {
		switch {
		case cfg.ZKBioURL == "":
			return Config{}, errors.New("missing zkbio_url")
		case cfg.ZKBioUsername == "":
			return Config{}, errors.New("missing zkbio_username")
		case cfg.ZKBioPassword == "":
			return Config{}, errors.New("missing zkbio_password")
		}
	}

	return cfg, nil
}

func (a *Agent) connectLoop() {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		err := a.connectSSE()
		if err != nil {
			log.Printf("SSE connection error: %v", err)
		}

		log.Printf("Reconnecting in %s...", backoff)
		time.Sleep(backoff)
		backoff = min(backoff*2, maxBackoff)
	}
}

func (a *Agent) startADMSServer() {
	log.Printf("ADMS server listening on :%d", a.config.ADMSPort)
	// TODO: implement in next task
}

func (a *Agent) connectSSE() error {
	connectURL := fmt.Sprintf("%s/api/agent-bridge/connect?apiKey=%s",
		a.config.PlamatixURL, url.QueryEscape(a.config.APIKey))

	req, err := http.NewRequest(http.MethodGet, connectURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("connect failed (HTTP %d): %s", res.StatusCode, string(body))
	}

	log.Printf("Connected to Plasmatix at %s", a.config.PlamatixURL)

	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		payload := strings.TrimPrefix(line, "data: ")

		var cmd struct {
			RequestID string            `json:"requestId"`
			Command   string            `json:"command"`
			Params    map[string]string `json:"params"`
			Type      string            `json:"type"`
		}

		if err := json.Unmarshal([]byte(payload), &cmd); err != nil {
			log.Printf("Invalid command: %v", err)
			continue
		}

		if cmd.RequestID == "" {
			if cmd.Type == "connected" {
				log.Println("SSE connection confirmed")
			}
			continue
		}

		go a.handleCommand(cmd.RequestID, cmd.Command, cmd.Params)
	}

	return scanner.Err()
}

func (a *Agent) handleCommand(requestId, command string, params map[string]string) {
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()

	var result any
	var cmdErr error

	switch command {
	case "health":
		result = map[string]any{
			"status":  "online",
			"version": version,
			"uptime":  time.Since(a.startedAt).Round(time.Second).String(),
		}
	case "info":
		result = a.collectSystemInfo()
	case "update":
		log.Println("Received update command — starting self-update...")
		updateErr := a.selfUpdate()
		if updateErr != nil {
			log.Printf("Update failed: %v", updateErr)
			result = map[string]any{"status": "failed", "error": updateErr.Error()}
		} else {
			result = map[string]any{"status": "restarting"}
			// Send response first, then restart
			a.postResponse(requestId, result, nil)
			a.restartService()
			return
		}
	case "uninstall":
		log.Println("Received uninstall command — starting self-removal...")
		result = map[string]any{"status": "uninstalling"}
		// Send response first, then uninstall in background
		a.postResponse(requestId, result, nil)
		go a.selfUninstall()
		return
	case "fetchEmployees":
		result, cmdErr = withZKBio(ctx, a.sessions, func(client *ZKBioClient) ([]ZKBioEmployee, error) {
			return client.FetchEmployees(ctx)
		})
	case "fetchTransactions":
		result, cmdErr = withZKBio(ctx, a.sessions, func(client *ZKBioClient) ([]ZKBioTransaction, error) {
			return client.FetchTransactions(ctx, params["start"], params["end"])
		})
	case "fetchDailyReport":
		result, cmdErr = withZKBio(ctx, a.sessions, func(client *ZKBioClient) ([]ZKBioDailyReport, error) {
			return client.FetchDailyReport(ctx, params["start"], params["end"])
		})
	case "fetchMonthlyReport":
		result, cmdErr = withZKBio(ctx, a.sessions, func(client *ZKBioClient) ([]ZKBioMonthlyReport, error) {
			return client.FetchMonthlyReport(ctx, params["month"], params["year"])
		})
	default:
		cmdErr = fmt.Errorf("unknown command: %s", command)
	}

	a.postResponse(requestId, result, cmdErr)
}

func (a *Agent) postResponse(requestId string, data any, cmdErr error) {
	payload := map[string]any{
		"requestId": requestId,
		"data":      data,
		"error":     nil,
	}
	if cmdErr != nil {
		payload["data"] = nil
		payload["error"] = cmdErr.Error()
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Marshal response error: %v", err)
		return
	}

	responseURL := fmt.Sprintf("%s/api/agent-bridge/response", a.config.PlamatixURL)
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		responseURL,
		strings.NewReader(string(body)),
	)
	if err != nil {
		log.Printf("Create response request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", a.config.APIKey)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		log.Printf("Post response error: %v", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		log.Printf("Post response failed (HTTP %d): %s", res.StatusCode, string(respBody))
	}
}

func (a *Agent) collectSystemInfo() map[string]any {
	info := map[string]any{
		"version":   version,
		"uptime":    time.Since(a.startedAt).Round(time.Second).String(),
		"startedAt": a.startedAt.UTC().Format(time.RFC3339),
		"go":        runtime.Version(),
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"pid":       os.Getpid(),
		"zkbioUrl":  a.config.ZKBioURL,
	}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		info["hostname"] = h
	}

	// OS release info
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info["osRelease"] = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	}

	// Memory info (Linux)
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

	// CPU count
	info["cpus"] = runtime.NumCPU()

	// Config path
	info["configPath"] = "/etc/plasmatix/agent.json"
	info["binPath"] = "/usr/local/bin/plasmatix-agent"

	// Systemd service status
	if out, err := exec.Command("systemctl", "is-active", "plasmatix-agent").Output(); err == nil {
		info["serviceStatus"] = strings.TrimSpace(string(out))
	}

	return info
}

func (a *Agent) selfUpdate() error {
	binPath := "/usr/local/bin/plasmatix-agent"
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	downloadURL := fmt.Sprintf("%s/api/releases/plasmatix-agent-%s-%s",
		a.config.PlamatixURL, goos, goarch)

	log.Printf("Downloading new binary from %s...", downloadURL)

	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed (HTTP %d)", resp.StatusCode)
	}

	// Write to temp file in the same directory (ensures same filesystem for rename)
	tmpFile, err := os.CreateTemp(filepath.Dir(binPath), "plasmatix-agent-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write binary: %w", err)
	}

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod: %w", err)
	}

	// Verify it's a real binary by running --version
	out, err := exec.Command(tmpPath, "--version").Output()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("verify binary: %w", err)
	}
	newVersion := strings.TrimSpace(string(out))
	log.Printf("New binary version: %s (current: %s)", newVersion, version)

	// Atomic replace: rename over existing binary
	if err := os.Rename(tmpPath, binPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	log.Println("Binary updated successfully")
	return nil
}

func (a *Agent) restartService() {
	time.Sleep(time.Second)
	log.Println("Restarting service...")
	cmd := exec.Command("systemctl", "restart", "plasmatix-agent")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("restart failed: %v — exiting to let systemd restart us", err)
		os.Exit(1)
	}
}

func (a *Agent) selfUninstall() {
	// Write a detached cleanup script that runs after this process is killed.
	// We can't do cleanup inline because `systemctl stop` sends SIGTERM to us.
	script := `#!/bin/bash
sleep 2
systemctl stop plasmatix-agent 2>/dev/null
systemctl disable plasmatix-agent 2>/dev/null
rm -f /etc/systemd/system/plasmatix-agent.service
systemctl daemon-reload 2>/dev/null
rm -rf /etc/plasmatix
rm -f /usr/local/bin/plasmatix-agent
rm -f /tmp/plasmatix-uninstall.sh
`
	scriptPath := "/tmp/plasmatix-uninstall.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		log.Printf("uninstall: write script: %v", err)
		return
	}

	log.Println("Launching detached uninstall script...")
	cmd := exec.Command("bash", scriptPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.Printf("uninstall: start script: %v", err)
		return
	}

	log.Println("Uninstall script launched — exiting")
	os.Exit(0)
}

func withZKBio[T any](
	ctx context.Context,
	sessions *SessionManager,
	fn func(*ZKBioClient) (T, error),
) (T, error) {
	client, err := sessions.Client(ctx, false)
	if err != nil {
		var zero T
		return zero, err
	}

	result, err := fn(client)
	if err == nil || !isSessionExpiredError(err) {
		return result, err
	}

	sessions.Invalidate()

	client, reloginErr := sessions.Client(ctx, true)
	if reloginErr != nil {
		var zero T
		return zero, reloginErr
	}

	return fn(client)
}

func (m *SessionManager) Client(ctx context.Context, force bool) (*ZKBioClient, error) {
	for {
		m.mu.Lock()

		if !force && m.client != nil && m.client.cookie != "" && time.Since(m.loginAt) < m.ttl {
			client := m.client
			m.mu.Unlock()
			return client, nil
		}

		if m.loginCh != nil {
			ch := m.loginCh
			m.mu.Unlock()

			select {
			case <-ch:
				force = false
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		ch := make(chan struct{})
		m.loginCh = ch
		m.mu.Unlock()

		client, err := newZKBioClient(ctx, m.config)

		m.mu.Lock()
		if err == nil {
			m.client = client
			m.loginAt = time.Now()
		}
		m.loginErr = err
		m.loginCh = nil
		close(ch)
		m.mu.Unlock()

		if err != nil {
			return nil, err
		}

		return client, nil
	}
}

func (m *SessionManager) Invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.client = nil
	m.loginAt = time.Time{}
}

func newZKBioClient(ctx context.Context, cfg Config) (*ZKBioClient, error) {
	client := &ZKBioClient{
		baseURL:  cfg.ZKBioURL,
		username: cfg.ZKBioUsername,
		password: cfg.ZKBioPassword,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	return client, client.Login(ctx)
}

func (c *ZKBioClient) Login(ctx context.Context) error {
	loginPageReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/bioLogin.do", nil)
	if err != nil {
		return err
	}

	loginPageRes, err := c.httpClient.Do(loginPageReq)
	if err != nil {
		return fmt.Errorf("load login page: %w", err)
	}
	defer loginPageRes.Body.Close()

	initialCookies := extractCookies(loginPageRes)

	passwordHash := md5.Sum([]byte(c.password))
	form := url.Values{
		"username":  {c.username},
		"password":  {hex.EncodeToString(passwordHash[:])},
		"loginType": {"NORMAL"},
	}

	loginReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/login.do",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}

	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if initialCookies != "" {
		loginReq.Header.Set("Cookie", initialCookies)
	}

	loginRes, err := c.httpClient.Do(loginReq)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer loginRes.Body.Close()

	body, err := io.ReadAll(loginRes.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	var payload loginResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("zkbio login returned unexpected response")
	}
	if !payload.Success {
		if payload.Msg == "" {
			payload.Msg = "unknown error"
		}
		return fmt.Errorf("zkbio login failed: %s", payload.Msg)
	}

	c.cookie = mergeCookies(initialCookies, extractCookies(loginRes))

	dashboardReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/dashboard.do?dashboard", nil)
	if err != nil {
		return err
	}
	if c.cookie != "" {
		dashboardReq.Header.Set("Cookie", c.cookie)
	}
	dashboardRes, err := c.httpClient.Do(dashboardReq)
	if err != nil {
		return fmt.Errorf("load dashboard: %w", err)
	}
	dashboardRes.Body.Close()

	return nil
}

func (c *ZKBioClient) FetchEmployees(ctx context.Context) ([]ZKBioEmployee, error) {
	data, err := c.postGrid(ctx, "persPerson.do", map[string]string{})
	if err != nil {
		return nil, err
	}

	employees := make([]ZKBioEmployee, 0, len(data.Rows))
	for _, row := range data.Rows {
		detail, err := c.FetchEmployeeDetail(ctx, row.ID)
		if err != nil {
			return nil, err
		}

		employees = append(employees, ZKBioEmployee{
			ID:             row.ID,
			PersonnelID:    stringAt(row.Data, 1),
			FirstName:      stringAt(row.Data, 2),
			LastName:       stringAt(row.Data, 3),
			DepartmentName: stringAt(row.Data, 4),
			CardNumber:     stringAt(row.Data, 5),
			Gender:         detail.Gender,
			HireDate:       detail.HireDate,
			Birthday:       detail.Birthday,
			Photo:          detail.Photo,
			CreateTime:     stringAt(row.Data, 9),
		})
	}

	return employees, nil
}

func (c *ZKBioClient) FetchEmployeeDetail(ctx context.Context, personID string) (ZKBioEmployeeDetail, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/persPerson.do?edit&id=%s", c.baseURL, url.QueryEscape(personID)),
		nil,
	)
	if err != nil {
		return ZKBioEmployeeDetail{}, err
	}
	req.Header.Set("Cookie", c.cookie)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return ZKBioEmployeeDetail{}, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ZKBioEmployeeDetail{}, err
	}
	html := string(body)
	if looksLikeLoginPage(html) {
		return ZKBioEmployeeDetail{}, errors.New("zkbio session expired")
	}

	genderCode := matchGroup(html, `<div[^>]*name=["']gender["'][^>]*value=["']([^"']*)["']`)
	gender := genderCode
	switch genderCode {
	case "M":
		gender = "Male"
	case "F":
		gender = "Female"
	}

	return ZKBioEmployeeDetail{
		Gender:   gender,
		HireDate: findInputValue(html, "hireDate"),
		Birthday: findInputValue(html, "birthday"),
		Photo:    matchGroup(html, `<img[^>]*id=["']id_img_pers["'][^>]*src=["'](data:image[^"']*)["']`),
	}, nil
}

func (c *ZKBioClient) FetchTransactions(ctx context.Context, dateFrom, dateTo string) ([]ZKBioTransaction, error) {
	data, err := c.postGrid(ctx, "attTransaction.do", map[string]string{
		"dateFrom": dateFrom,
		"dateTo":   dateTo,
	})
	if err != nil {
		return nil, err
	}

	transactions := make([]ZKBioTransaction, 0, len(data.Rows))
	for _, row := range data.Rows {
		item := ZKBioTransaction{
			ID:          row.ID,
			PersonnelID: stringAt(row.Data, 0),
			Name:        strings.TrimSpace(strings.Join([]string{stringAt(row.Data, 1), stringAt(row.Data, 2)}, " ")),
			Department:  stringAt(row.Data, 3),
			PunchTime:   stringAt(row.Data, 7),
			DeviceName:  firstNonEmpty(stringAt(row.Data, 6), stringAt(row.Data, 11)),
			Status:      stringAt(row.Data, 8),
			VerifyMode:  stringAt(row.Data, 9),
		}

		date := item.PunchTime
		if len(date) >= 10 {
			date = date[:10]
		}
		if date >= dateFrom && date <= dateTo {
			transactions = append(transactions, item)
		}
	}

	return transactions, nil
}

func (c *ZKBioClient) FetchDailyReport(ctx context.Context, dateFrom, dateTo string) ([]ZKBioDailyReport, error) {
	data, err := c.postGrid(ctx, "attDayDetailReport.do", map[string]string{
		"dateFrom": dateFrom,
		"dateTo":   dateTo,
	})
	if err != nil {
		return nil, err
	}

	report := make([]ZKBioDailyReport, 0, len(data.Rows))
	for _, row := range data.Rows {
		item := ZKBioDailyReport{
			ID:                 row.ID,
			PersonnelID:        stringAt(row.Data, 0),
			Name:               strings.TrimSpace(strings.Join([]string{stringAt(row.Data, 1), stringAt(row.Data, 2)}, " ")),
			Department:         stringAt(row.Data, 3),
			Date:               stringAt(row.Data, 4),
			Week:               stringAt(row.Data, 5),
			TimetableName:      stringAt(row.Data, 6),
			WorkTime:           stringAt(row.Data, 7),
			PunchData:          stringAt(row.Data, 8),
			PunchCounts:        stringAt(row.Data, 9),
			ShouldMinutes:      stringAt(row.Data, 10),
			ActualMinutes:      stringAt(row.Data, 11),
			ValidMinutes:       stringAt(row.Data, 12),
			LateCounts:         stringAt(row.Data, 13),
			LateDuration:       stringAt(row.Data, 14),
			LateTotal:          stringAt(row.Data, 15),
			EarlyCounts:        stringAt(row.Data, 16),
			EarlyDuration:      stringAt(row.Data, 17),
			EarlyTotal:         stringAt(row.Data, 18),
			OvertimeWeekday:    stringAt(row.Data, 19),
			OvertimeWeekend:    stringAt(row.Data, 20),
			OvertimeHoliday:    stringAt(row.Data, 21),
			OvertimeTotal:      stringAt(row.Data, 22),
			AbsentHours:        stringAt(row.Data, 23),
			PersonalLeave:      stringAt(row.Data, 24),
			AnnualLeave:        stringAt(row.Data, 25),
			SickLeave:          stringAt(row.Data, 26),
			MarriageLeave:      stringAt(row.Data, 27),
			MaternityLeave:     stringAt(row.Data, 28),
			BreastfeedingLeave: stringAt(row.Data, 29),
			HomeLeave:          stringAt(row.Data, 30),
			BereavementLeave:   stringAt(row.Data, 31),
			BusinessTrip:       stringAt(row.Data, 32),
			OutHours:           stringAt(row.Data, 33),
		}

		date := item.Date
		if len(date) >= 10 {
			date = date[:10]
		}
		if date >= dateFrom && date <= dateTo {
			report = append(report, item)
		}
	}

	return report, nil
}

func (c *ZKBioClient) FetchMonthlyReport(ctx context.Context, month, year string) ([]ZKBioMonthlyReport, error) {
	monthInt, err := strconv.Atoi(month)
	if err != nil {
		return nil, fmt.Errorf("invalid month")
	}
	yearInt, err := strconv.Atoi(year)
	if err != nil {
		return nil, fmt.Errorf("invalid year")
	}

	lastDay := time.Date(yearInt, time.Month(monthInt)+1, 0, 0, 0, 0, 0, time.UTC).Day()
	monthStart := fmt.Sprintf("%04d-%02d-01", yearInt, monthInt)
	monthEnd := fmt.Sprintf("%04d-%02d-%02d", yearInt, monthInt, lastDay)

	data, err := c.postGridDirect(ctx, "attMonthDetailReport.do", map[string]string{
		"monthStart": monthStart,
		"monthEnd":   monthEnd,
	})
	if err != nil {
		return nil, err
	}

	report := make([]ZKBioMonthlyReport, 0, len(data.Rows))
	for _, row := range data.Rows {
		report = append(report, ZKBioMonthlyReport{
			ID:             row.ID,
			PersonnelID:    stringAt(row.Data, 0),
			Name:           strings.TrimSpace(strings.Join([]string{stringAt(row.Data, 1), stringAt(row.Data, 2)}, " ")),
			Department:     stringAt(row.Data, 3),
			TotalDays:      stringAt(row.Data, 4),
			PresentDays:    stringAt(row.Data, 5),
			AbsentDays:     stringAt(row.Data, 6),
			LateDays:       stringAt(row.Data, 7),
			EarlyLeaveDays: stringAt(row.Data, 8),
			OvertimeHours:  stringAt(row.Data, 9),
		})
	}

	return report, nil
}

func (c *ZKBioClient) postGrid(ctx context.Context, endpoint string, params map[string]string) (gridResponse, error) {
	form := url.Values{}
	for key, value := range params {
		form.Set(key, value)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/"+endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return gridResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", c.cookie)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return gridResponse{}, err
	}
	res.Body.Close()

	const pageSize = 50
	allRows := make([]gridRow, 0, pageSize)
	totalCount := 0

	for posStart := 0; ; posStart += pageSize {
		listReq, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			fmt.Sprintf("%s/%s?list&count=%d&posStart=%d", c.baseURL, endpoint, pageSize, posStart),
			nil,
		)
		if err != nil {
			return gridResponse{}, err
		}
		listReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		listReq.Header.Set("Cookie", c.cookie)
		listReq.Header.Set("X-Requested-With", "XMLHttpRequest")

		listRes, err := c.httpClient.Do(listReq)
		if err != nil {
			return gridResponse{}, err
		}

		page, err := parseGridResponse(endpoint, listRes)
		if err != nil {
			return gridResponse{}, err
		}

		allRows = append(allRows, page.Rows...)
		totalCount = page.TotalCount
		if totalCount == 0 {
			totalCount = page.Total
		}
		if len(page.Rows) < pageSize || len(allRows) >= totalCount {
			break
		}
	}

	return gridResponse{
		Rows:       allRows,
		TotalCount: totalCount,
		Total:      totalCount,
		Pos:        0,
	}, nil
}

func (c *ZKBioClient) postGridDirect(ctx context.Context, endpoint string, params map[string]string) (gridResponse, error) {
	form := url.Values{}
	for key, value := range params {
		form.Set(key, value)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/%s?list&count=100000&posStart=0", c.baseURL, endpoint),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return gridResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", c.cookie)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return gridResponse{}, err
	}

	return parseGridResponse(endpoint, res)
}

func parseGridResponse(endpoint string, res *http.Response) (gridResponse, error) {
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return gridResponse{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return gridResponse{}, fmt.Errorf("zkbio %s failed: %s", endpoint, res.Status)
	}

	var payload gridResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		text := string(body)
		if looksLikeLoginPage(text) {
			return gridResponse{}, errors.New("zkbio session expired")
		}
		return gridResponse{}, fmt.Errorf("zkbio %s returned invalid json", endpoint)
	}
	if payload.Rows == nil {
		text := string(body)
		if strings.Contains(text, `"ret":"401"`) || strings.Contains(text, `"ret":401`) || looksLikeLoginPage(text) {
			return gridResponse{}, errors.New("zkbio session expired")
		}
		return gridResponse{}, fmt.Errorf("zkbio %s returned unexpected response", endpoint)
	}

	return payload, nil
}

func extractCookies(res *http.Response) string {
	cookies := res.Header.Values("Set-Cookie")
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		piece := strings.SplitN(cookie, ";", 2)[0]
		if piece != "" {
			parts = append(parts, piece)
		}
	}
	return strings.Join(parts, "; ")
}

func mergeCookies(values ...string) string {
	pairs := map[string]string{}
	for _, value := range values {
		for _, piece := range strings.Split(value, ";") {
			piece = strings.TrimSpace(piece)
			if piece == "" {
				continue
			}
			parts := strings.SplitN(piece, "=", 2)
			if len(parts) != 2 {
				continue
			}
			pairs[parts[0]] = parts[1]
		}
	}

	merged := make([]string, 0, len(pairs))
	for key, value := range pairs {
		merged = append(merged, key+"="+value)
	}
	return strings.Join(merged, "; ")
}

func isSessionExpiredError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "session expired")
}

func looksLikeLoginPage(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "biologin") || (strings.Contains(lower, "<html") && strings.Contains(lower, "login"))
}

func findInputValue(html, name string) string {
	patterns := []string{
		fmt.Sprintf(`<input[^>]*name=["']%s["'][^>]*value=["']([^"']*)["']`, regexp.QuoteMeta(name)),
		fmt.Sprintf(`<input[^>]*value=["']([^"']*)["'][^>]*name=["']%s["']`, regexp.QuoteMeta(name)),
	}
	for _, pattern := range patterns {
		if value := matchGroup(html, pattern); value != "" {
			return value
		}
	}
	return ""
}

func matchGroup(input, pattern string) string {
	re := regexp.MustCompile("(?is)" + pattern)
	match := re.FindStringSubmatch(input)
	if len(match) < 2 {
		return ""
	}
	return htmlUnescape(strings.TrimSpace(match[1]))
}

func htmlUnescape(value string) string {
	replacer := strings.NewReplacer(
		"&amp;", "&",
		"&quot;", `"`,
		"&#39;", "'",
		"&lt;", "<",
		"&gt;", ">",
	)
	return replacer.Replace(value)
}

func stringAt(values []any, index int) string {
	if index < 0 || index >= len(values) || values[index] == nil {
		return ""
	}

	switch value := values[index].(type) {
	case string:
		return value
	case float64:
		if float64(int64(value)) == value {
			return strconv.FormatInt(int64(value), 10)
		}
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		if value {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(value)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

