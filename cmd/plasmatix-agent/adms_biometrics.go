package main

import (
	"strconv"
	"strings"
)

type CommandAction string

const (
	CommandPassedThrough CommandAction = "passed_through"
	CommandTranslated    CommandAction = "translated"
	CommandRefused       CommandAction = "refused"
)

type CommandDecision struct {
	Rendered string
	Action   CommandAction
	Reason   string
}

func RenderDeviceCommand(state DeviceProtocolState, command string) CommandDecision {
	passedThrough := CommandDecision{
		Rendered: command,
		Action:   CommandPassedThrough,
		Reason:   "device profile does not require translation",
	}
	if state.Profile != ProtocolTAPush || state.Confidence < 80 {
		return passedThrough
	}

	name, fields := parseDeviceCommand(command)
	if name == "DATA UPDATE BIODATA" && fields["TYPE"] == "1" {
		return renderTAFingerprintWrite(state, fields, passedThrough)
	}
	if name == "DATA DELETE BIODATA" && fields["TYPE"] == "1" {
		return renderTAFingerprintDelete(state, fields, passedThrough)
	}
	if name != "ENROLL_BIO" || fields["TYPE"] != "1" {
		return passedThrough
	}

	pin, hasPIN := fields["PIN"]
	fid, hasFID := fields["NO"]
	if !hasPIN || !hasFID {
		return CommandDecision{
			Action: CommandRefused,
			Reason: "TA fingerprint enrollment requires PIN and NO",
		}
	}

	rendered := "ENROLL_FP PIN=" + pin + "\tFID=" + fid
	for _, key := range []string{"RETRY", "OVERWRITE"} {
		if value, ok := fields[key]; ok {
			rendered += "\t" + key + "=" + value
		}
	}
	return CommandDecision{
		Rendered: rendered,
		Action:   CommandTranslated,
		Reason:   "TA PUSH uses ENROLL_FP for fingerprint enrollment",
	}
}

func parseDeviceCommand(command string) (string, map[string]string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", nil
	}

	name := strings.ToUpper(parts[0])
	fieldStart := 1
	if len(parts) >= 3 && strings.EqualFold(parts[0], "DATA") {
		name = strings.ToUpper(strings.Join(parts[:3], " "))
		fieldStart = 3
	}

	fields := make(map[string]string, len(parts)-fieldStart)
	for _, part := range parts[fieldStart:] {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		fields[strings.ToUpper(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return name, fields
}

func renderTAFingerprintWrite(
	state DeviceProtocolState,
	fields map[string]string,
	passedThrough CommandDecision,
) CommandDecision {
	templateMajor, templateMajorOK := positiveInt(fields["MAJORVER"])
	templateMinor, templateMinorOK := nonNegativeInt(fields["MINORVER"])
	if !templateMajorOK || !templateMinorOK {
		return CommandDecision{
			Action: CommandRefused,
			Reason: "fingerprint template is missing an exact algorithm version",
		}
	}

	if templateMajor <= 10 {
		pin, hasPIN := fields["PIN"]
		fid, hasFID := fields["NO"]
		template, hasTemplate := fields["TMP"]
		if !hasPIN || !hasFID || !hasTemplate {
			return CommandDecision{
				Action: CommandRefused,
				Reason: "fingerprint write requires Pin, No, and Tmp",
			}
		}
		recordName := "DATA UPDATE FINGERTMP"
		reason := "TA PUSH fingerprint algorithm 10 or older uses FINGERTMP"
		if pushVersionBefore(state.PushVersion, 2, 2, 14) {
			recordName = "DATA FP"
			reason = "TA PUSH older than 2.2.14 uses DATA FP"
		}
		return CommandDecision{
			Rendered: recordName + " PIN=" + pin +
				"\tFID=" + fid +
				"\tSize=" + strconv.Itoa(decodedTemplateSize(template)) +
				"\tValid=1\tTMP=" + template,
			Action: CommandTranslated,
			Reason: reason,
		}
	}

	deviceMajor, deviceMinor, deviceVersionOK := algorithmVersion(
		state.Capabilities["fingeralgorithmversion"],
	)
	if !deviceVersionOK {
		return CommandDecision{
			Action: CommandRefused,
			Reason: "device did not report a fingerprint algorithm version",
		}
	}
	if deviceMajor != templateMajor || deviceMinor != templateMinor {
		return CommandDecision{
			Action: CommandRefused,
			Reason: "fingerprint template algorithm version does not match device",
		}
	}

	passedThrough.Reason = "device and template fingerprint algorithm versions match"
	return passedThrough
}

func renderTAFingerprintDelete(
	state DeviceProtocolState,
	fields map[string]string,
	passedThrough CommandDecision,
) CommandDecision {
	deviceMajor, _, versionOK := algorithmVersion(
		state.Capabilities["fingeralgorithmversion"],
	)
	if !versionOK {
		return CommandDecision{
			Action: CommandRefused,
			Reason: "device did not report a fingerprint algorithm version",
		}
	}
	if deviceMajor > 10 {
		passedThrough.Reason = "modern TA fingerprint deletion uses BIODATA"
		return passedThrough
	}

	pin, hasPIN := fields["PIN"]
	fid, hasFID := fields["NO"]
	if !hasPIN || !hasFID {
		return CommandDecision{
			Action: CommandRefused,
			Reason: "fingerprint deletion requires Pin and No",
		}
	}
	return CommandDecision{
		Rendered: "DATA DELETE FINGERTMP PIN=" + pin + "\tFID=" + fid,
		Action:   CommandTranslated,
		Reason:   "TA fingerprint algorithm 10 or older uses FINGERTMP deletion",
	}
}

func algorithmVersion(value string) (int, int, bool) {
	if _, version, ok := strings.Cut(value, ":"); ok {
		value = version
	}
	majorText, minorText, ok := strings.Cut(strings.TrimSpace(value), ".")
	if !ok {
		return 0, 0, false
	}
	major, majorOK := positiveInt(majorText)
	minor, minorOK := nonNegativeInt(minorText)
	return major, minor, majorOK && minorOK
}

func positiveInt(value string) (int, bool) {
	number, err := strconv.Atoi(strings.TrimSpace(value))
	return number, err == nil && number > 0
}

func nonNegativeInt(value string) (int, bool) {
	number, err := strconv.Atoi(strings.TrimSpace(value))
	return number, err == nil && number >= 0
}

func pushVersionBefore(value string, major, minor, patch int) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 3 {
		return false
	}
	actual := [3]int{}
	for index := range actual {
		number, err := strconv.Atoi(parts[index])
		if err != nil {
			return false
		}
		actual[index] = number
	}
	required := [3]int{major, minor, patch}
	for index := range actual {
		if actual[index] != required[index] {
			return actual[index] < required[index]
		}
	}
	return false
}
