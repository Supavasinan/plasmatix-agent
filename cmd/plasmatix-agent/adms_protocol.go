package main

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ProtocolProfile string

const (
	ProtocolUnknown ProtocolProfile = "unknown"
	ProtocolTAPush  ProtocolProfile = "ta_push"
	ProtocolACPush3 ProtocolProfile = "ac_push_3"
)

type DeviceProtocolState struct {
	Profile      ProtocolProfile   `json:"profile"`
	Confidence   int               `json:"confidence"`
	PushVersion  string            `json:"pushVersion,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	Evidence     []string          `json:"evidence,omitempty"`
	ObservedAt   time.Time         `json:"observedAt"`
}

type ProtocolObservation struct {
	Path         string
	PushVersion  string
	Capabilities map[string]string
}

var reportedCapabilityKeys = map[string]struct{}{
	"fingerfunon":                {},
	"facefunon":                  {},
	"photofunon":                 {},
	"biophotofun":                {},
	"biodatafun":                 {},
	"visilightfun":               {},
	"fvfunon":                    {},
	"pvfunon":                    {},
	"multibiodatasupport":        {},
	"multibiophotosupport":       {},
	"multibioversion":            {},
	"fingeralgorithmversion":     {},
	"facealgorithmversion":       {},
	"fingerveinalgorithmversion": {},
	"palmalgorithmversion":       {},
}

const invalidReportedCapability = "invalid"

func capabilitiesFromQuery(values url.Values) map[string]string {
	capabilities := make(map[string]string)
	seen := make(map[string]struct{})
	for key, entries := range values {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if _, ok := reportedCapabilityKeys[normalizedKey]; !ok || len(entries) == 0 {
			continue
		}
		_, duplicatedKey := seen[normalizedKey]
		seen[normalizedKey] = struct{}{}
		if duplicatedKey || len(entries) != 1 {
			capabilities[normalizedKey] = invalidReportedCapability
			continue
		}
		capabilities[normalizedKey] = strings.TrimSpace(entries[0])
	}
	if len(capabilities) == 0 {
		return nil
	}
	return capabilities
}

func ObserveProtocol(current DeviceProtocolState, observation ProtocolObservation) DeviceProtocolState {
	if observation.Path == "/iclock/registry" || observation.Path == "/iclock/push" {
		if current.Profile == ProtocolTAPush && current.Confidence >= 80 {
			return DeviceProtocolState{
				Profile:    ProtocolUnknown,
				Confidence: 0,
				Evidence:   appendEvidence(current.Evidence, "conflicting_ac_push_route"),
				ObservedAt: time.Now(),
			}
		}
		return DeviceProtocolState{
			Profile:    ProtocolACPush3,
			Confidence: 95,
			Evidence:   appendEvidence(current.Evidence, "ac_push_route"),
			ObservedAt: time.Now(),
		}
	}

	parts := strings.Split(observation.PushVersion, ".")
	if len(parts) >= 2 {
		major, majorErr := strconv.Atoi(parts[0])
		minor, minorErr := strconv.Atoi(parts[1])
		if majorErr == nil && minorErr == nil && major == 2 && minor >= 2 && minor <= 4 {
			if current.Profile == ProtocolACPush3 && current.Confidence >= 80 {
				return DeviceProtocolState{
					Profile:      ProtocolUnknown,
					Confidence:   0,
					PushVersion:  observation.PushVersion,
					Capabilities: normalizeCapabilities(observation.Capabilities),
					Evidence:     appendEvidence(current.Evidence, "conflicting_ta_push_version"),
					ObservedAt:   time.Now(),
				}
			}
			return DeviceProtocolState{
				Profile:      ProtocolTAPush,
				Confidence:   90,
				PushVersion:  observation.PushVersion,
				Capabilities: normalizeCapabilities(observation.Capabilities),
				Evidence:     []string{"push_version_2_x"},
				ObservedAt:   time.Now(),
			}
		}
	}

	return current
}

func normalizeCapabilities(capabilities map[string]string) map[string]string {
	if capabilities == nil {
		return nil
	}
	normalized := make(map[string]string, len(capabilities))
	for key, value := range capabilities {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if _, duplicated := normalized[normalizedKey]; duplicated {
			normalized[normalizedKey] = invalidReportedCapability
			continue
		}
		normalized[normalizedKey] = strings.TrimSpace(value)
	}
	return normalized
}

func appendEvidence(evidence []string, item string) []string {
	if len(evidence) >= 16 {
		evidence = evidence[len(evidence)-15:]
	}
	out := append([]string(nil), evidence...)
	return append(out, item)
}

func cloneProtocolState(state DeviceProtocolState) DeviceProtocolState {
	state.Evidence = append([]string(nil), state.Evidence...)
	if state.Capabilities != nil {
		source := state.Capabilities
		state.Capabilities = make(map[string]string, len(source))
		for key, value := range source {
			state.Capabilities[key] = value
		}
	}
	return state
}
