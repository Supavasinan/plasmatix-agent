package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The heartbeat is the bridge's source of truth for "is the agent alive on
// the customer LAN?" and "is the SenseFace 2A reachable from the agent?"
//
// Two device signals are reported:
//
//  - LastContactAt — passive: the most recent ADMS push the agent received
//    from the device. Strong positive when fresh; useless when no scans are
//    happening.
//  - LastProbeAt + ProbeOk — active: result of a TCP-connect to ip:4370.
//    Cheap (one handshake/min/device on the LAN) and gives a definitive
//    "device is offline" signal even when nobody is scanning.
//
// See docs/runbooks/agent-heartbeat.md in the Plasmatix repo for the contract.

const (
	deviceProbePort      = "4370"
	heartbeatInterval    = 30 * time.Second
	deviceProbeInterval  = 60 * time.Second
	deviceProbeTimeout   = 3 * time.Second
	heartbeatHTTPTimeout = 10 * time.Second
)

type deviceState struct {
	SN            string
	IP            string
	LastContactAt time.Time
	LastProbeAt   time.Time
	ProbeOk       *bool
	Protocol      DeviceProtocolState
}

type DeviceTracker struct {
	mu      sync.Mutex
	devices map[string]*deviceState
}

func newDeviceTracker() *DeviceTracker {
	return &DeviceTracker{devices: make(map[string]*deviceState)}
}

// noteContact records a device→agent ADMS contact. remoteAddr is the
// http.Request's RemoteAddr ("host:port"); pass "" if unknown.
func (t *DeviceTracker) noteContact(sn, remoteAddr string) {
	if sn == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.devices[sn]
	if !ok {
		d = &deviceState{
			SN:       sn,
			Protocol: DeviceProtocolState{Profile: ProtocolUnknown},
		}
		t.devices[sn] = d
	}
	d.LastContactAt = time.Now()
	if remoteAddr != "" {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			host = remoteAddr
		}
		d.IP = host
	}
}

func (t *DeviceTracker) observeProtocol(sn string, observation ProtocolObservation) {
	if sn == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	d, ok := t.devices[sn]
	if !ok {
		d = &deviceState{
			SN:       sn,
			Protocol: DeviceProtocolState{Profile: ProtocolUnknown},
		}
		t.devices[sn] = d
	}
	d.Protocol = cloneProtocolState(ObserveProtocol(d.Protocol, observation))
}

func (t *DeviceTracker) protocolState(sn string) (DeviceProtocolState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	d, ok := t.devices[sn]
	if !ok {
		return DeviceProtocolState{}, false
	}
	return cloneProtocolState(d.Protocol), true
}

func (t *DeviceTracker) recordProbe(sn string, ok bool, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, exists := t.devices[sn]
	if !exists {
		return
	}
	d.LastProbeAt = at
	v := ok
	d.ProbeOk = &v
}

func (t *DeviceTracker) snapshot() []deviceState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]deviceState, 0, len(t.devices))
	for _, d := range t.devices {
		snapshot := *d
		snapshot.Protocol = cloneProtocolState(d.Protocol)
		out = append(out, snapshot)
	}
	return out
}

// probeAll runs a TCP-connect to ip:4370 for every known device. We only
// probe devices we've seen at least once — a zero IP means we don't know
// where to reach them yet.
func (t *DeviceTracker) probeAll(ctx context.Context) {
	for _, d := range t.snapshot() {
		if d.IP == "" {
			continue
		}
		ok := tcpProbe(ctx, d.IP)
		t.recordProbe(d.SN, ok, time.Now())
	}
}

func tcpProbe(ctx context.Context, ip string) bool {
	dialer := net.Dialer{Timeout: deviceProbeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, deviceProbePort))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

type heartbeatDevice struct {
	SN                   string            `json:"sn"`
	LastContactAt        *string           `json:"lastContactAt,omitempty"`
	LastProbeAt          *string           `json:"lastProbeAt,omitempty"`
	ProbeOk              *bool             `json:"probeOk,omitempty"`
	ProtocolProfile      ProtocolProfile   `json:"protocolProfile"`
	ProtocolConfidence   int               `json:"protocolConfidence"`
	PushVersion          string            `json:"pushVersion,omitempty"`
	ProtocolCapabilities map[string]string `json:"protocolCapabilities,omitempty"`
	ProtocolEvidence     []string          `json:"protocolEvidence,omitempty"`
	ProtocolObservedAt   *string           `json:"protocolObservedAt,omitempty"`
}

type heartbeatPayload struct {
	Devices []heartbeatDevice `json:"devices"`
}

func (a *Agent) postHeartbeat(ctx context.Context) error {
	var devices []heartbeatDevice
	if a.devices != nil {
		for _, d := range a.devices.snapshot() {
			hd := heartbeatDevice{
				SN:                   d.SN,
				ProtocolProfile:      d.Protocol.Profile,
				ProtocolConfidence:   d.Protocol.Confidence,
				PushVersion:          d.Protocol.PushVersion,
				ProtocolCapabilities: d.Protocol.Capabilities,
				ProtocolEvidence:     d.Protocol.Evidence,
			}
			if !d.LastContactAt.IsZero() {
				s := d.LastContactAt.UTC().Format(time.RFC3339)
				hd.LastContactAt = &s
			}
			if !d.LastProbeAt.IsZero() {
				s := d.LastProbeAt.UTC().Format(time.RFC3339)
				hd.LastProbeAt = &s
			}
			if d.ProbeOk != nil {
				hd.ProbeOk = d.ProbeOk
			}
			if !d.Protocol.ObservedAt.IsZero() {
				s := d.Protocol.ObservedAt.UTC().Format(time.RFC3339)
				hd.ProtocolObservedAt = &s
			}
			devices = append(devices, hd)
		}
	}

	body, err := json.Marshal(heartbeatPayload{Devices: devices})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	hbURL := fmt.Sprintf("%s/api/agent-bridge/heartbeat", a.config.PlamatixURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hbURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", a.config.APIKey)

	client := cloudHTTPClient(heartbeatHTTPTimeout)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (a *Agent) runHeartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	// First post fires immediately so the bridge picks us up without waiting
	// a full interval after startup.
	if err := a.postHeartbeat(ctx); err != nil {
		log.Printf("[heartbeat] initial post failed: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.postHeartbeat(ctx); err != nil {
				log.Printf("[heartbeat] post failed: %v", err)
			}
		}
	}
}

func (a *Agent) runProbeLoop(ctx context.Context) {
	ticker := time.NewTicker(deviceProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.devices.probeAll(ctx)
		}
	}
}
