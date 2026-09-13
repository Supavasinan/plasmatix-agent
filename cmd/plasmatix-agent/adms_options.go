package main

import (
	"strconv"
	"strings"
)

// The device answers the handshake's PushOptions request with a
// POST /iclock/cdata?SN=...&table=options body of `Key=Value` pairs separated
// by commas and newlines. It is the only place the scanner ever states what it
// can actually do — algorithm versions, which biometric record types it
// accepts, how many users it can hold. Everything Plasmatix needs to decide
// whether a template is safe to deliver comes from here.
//
// Captured from a SenseFace 2A (ZAM70-NF24HA-Ver3.3.12, PushVersion
// "Ver 3.1.2S-20250616"):
//
//	~DeviceName=SenseFace 2A,FingerFunOn=1,FPVersion=13,FaceFunOn=1,
//	FaceVersion=40,BioPhotoFun=1,BioDataFun=,
//	MultiBioDataSupport=0:1:0:0:0:0:0:0:0:1,
//	MultiBioVersion=0:13.0:0:0:0:0:0:0:0:40.1

// ZKTeco indexes every multi-biometric field by modality. Index 1 is the
// fingerprint slot and index 9 the visible-light face slot; the intermediate
// slots (voice, iris, retina, palmprint, finger vein, palm) are unused by this
// hardware and report 0.
const (
	multiBioIndexFingerprint = 1
	multiBioIndexFace        = 9
)

// parseDeviceOptions splits an options payload into its raw key/value pairs.
// Keys keep their original spelling; ZKTeco prefixes read-only fields with '~'
// (~MaxUserCount) and the caller needs to see that distinction.
func parseDeviceOptions(body []byte) map[string]string {
	options := make(map[string]string)
	fields := strings.FieldsFunc(string(body), func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		options[key] = strings.TrimSpace(value)
	}
	if len(options) == 0 {
		return nil
	}
	return options
}

// multiBioSlot pulls one modality out of a colon-indexed ZKTeco list such as
// MultiBioVersion or MultiBioDataSupport. A short list means the firmware does
// not report that modality at all, which is not the same as reporting zero.
func multiBioSlot(value string, index int) (string, bool) {
	if value == "" {
		return "", false
	}
	parts := strings.Split(value, ":")
	if index >= len(parts) {
		return "", false
	}
	slot := strings.TrimSpace(parts[index])
	if slot == "" {
		return "", false
	}
	return slot, true
}

// capabilitiesFromOptions maps a raw options payload onto the canonical
// capability keys the cloud's compatibility check reads.
//
// Two firmware quirks are handled here rather than at the call site:
//
//   - BioDataFun comes back *empty* on this SenseFace firmware even though the
//     device plainly accepts BIODATA records — MultiBioDataSupport advertises
//     both the fingerprint and the face slot. Trusting the blank flag would
//     permanently reject every template for a device that supports them, so the
//     per-slot list wins when the scalar flag is absent.
//
//   - Algorithm versions are reported twice, as scalar FPVersion/FaceVersion
//     ("13", "40") and inside MultiBioVersion ("0:13.0:...:40.1"). Only the
//     latter carries the minor version, and the cloud compares major *and*
//     minor exactly, so the indexed list is preferred and the scalar is a
//     fallback that assumes minor 0.
func capabilitiesFromOptions(options map[string]string) map[string]string {
	if len(options) == 0 {
		return nil
	}

	lookup := make(map[string]string, len(options))
	for key, value := range options {
		lookup[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(key, "~")))] = value
	}

	capabilities := make(map[string]string)
	for _, key := range []string{
		"fingerfunon", "facefunon", "photofunon", "biophotofun",
		"visilightfun", "fvfunon", "pvfunon",
		"multibiodatasupport", "multibiophotosupport", "multibioversion",
	} {
		if value, ok := lookup[key]; ok && value != "" {
			capabilities[key] = value
		}
	}

	if value, ok := lookup["biodatafun"]; ok && value != "" {
		capabilities["biodatafun"] = value
	} else if supportsAnyBioDataSlot(lookup["multibiodatasupport"]) {
		capabilities["biodatafun"] = "1"
	}

	if version, ok := optionAlgorithmVersion(lookup, multiBioIndexFingerprint, "fpversion"); ok {
		capabilities["fingeralgorithmversion"] = version
	}
	if version, ok := optionAlgorithmVersion(lookup, multiBioIndexFace, "faceversion"); ok {
		capabilities["facealgorithmversion"] = version
	}

	if len(capabilities) == 0 {
		return nil
	}
	return capabilities
}

// supportsAnyBioDataSlot reports whether MultiBioDataSupport marks at least one
// modality as accepting BIODATA records.
func supportsAnyBioDataSlot(value string) bool {
	if value == "" {
		return false
	}
	for _, slot := range strings.Split(value, ":") {
		if strings.TrimSpace(slot) == "1" {
			return true
		}
	}
	return false
}

// optionAlgorithmVersion resolves one modality's algorithm version to the exact
// "major.minor" form the cloud compares against a stored template.
func optionAlgorithmVersion(
	lookup map[string]string,
	index int,
	scalarKey string,
) (string, bool) {
	if slot, ok := multiBioSlot(lookup["multibioversion"], index); ok {
		if slot == "0" {
			return "", false
		}
		if !strings.Contains(slot, ".") {
			return slot + ".0", true
		}
		return slot, true
	}
	scalar := strings.TrimSpace(lookup[scalarKey])
	if scalar == "" || scalar == "0" {
		return "", false
	}
	if !strings.Contains(scalar, ".") {
		return scalar + ".0", true
	}
	return scalar, true
}

// pushOptionsRequest is the capability list the server asks the device to
// report. Without it the firmware never sends its options block, so the
// algorithm versions and record-type flags stay unknown and no biometric
// template can ever clear the cloud's compatibility check.
//
// Copied from what ZKBioTime 8 asks this hardware for, verified against a
// packet capture of the live SenseFace 2A rather than from documentation.
const pushOptionsRequest = "UserCount,TransactionCount,FingerFunOn,FPVersion," +
	"FPCount,FaceFunOn,FaceVersion,FaceCount,FvFunOn,FvVersion,FvCount," +
	"PvFunOn,PvVersion,PvCount,BioPhotoFun,BioDataFun,PhotoFunOn,~LockFunOn," +
	"CardProtFormat,~Platform,MultiBioPhotoSupport,MultiBioDataSupport," +
	"MultiBioVersion"

// TransFlag tokens are separated by TABs, not spaces. Push 3.x firmware parses
// the value by splitting on tab; with spaces it reads the whole run as one
// unknown token and silently declines to push anything but attendance — which
// is why face templates and BioPhoto never arrived under the old handshake.
const transFlagTokens = "TransData AttLog\tOpLog\tAttPhoto\tEnrollFP\t" +
	"EnrollUser\tFPImag\tChgUser\tChgFP\tFACE\tUserPic\tFVEIN\tBioPhoto"

// Upload-pointer key spellings. ZKBioTime speaks push3 to this hardware; the
// agent's own production history proves legacy works. Which one a given
// firmware honours has to be observed, not assumed — see Config.StampStyle.
const (
	stampStyleLegacy = "legacy"
	stampStylePush3  = "push3"
)

// defaultDeviceTimeZone matches the site the agent was built for (UTC+7).
const defaultDeviceTimeZone = 7

// buildHandshakeOptions renders the GET /iclock/cdata handshake response.
//
// The field set mirrors ZKBioTime's reply to the same device, since that is the
// only configuration this hardware is known to accept.
func buildHandshakeOptions(sn, stamp, stampStyle string, timeZone int) string {
	attKey, opKey, photoKey := "ATTLOGStamp", "OPERLOGStamp", "ATTPHOTOStamp"
	if stampStyle == stampStylePush3 {
		attKey, opKey, photoKey = "Stamp", "OpStamp", "PhotoStamp"
	}

	lines := []string{
		"GET OPTION FROM: " + sn,
		"TransFlag=" + transFlagTokens,
		"ServerVer=2.4.1",
		"PushProtVer=2.4.1",
		"Encrypt=0",
		"EncryptFlag=1000000000",
		"SupportPing=1",
		"PushOptionsFlag=1",
		"MaxPostSize=1048576",
		"PushOptions=" + pushOptionsRequest,
		attKey + "=" + stamp,
		opKey + "=" + stamp,
		photoKey + "=None",
		"TimeZone=" + strconv.Itoa(timeZone),
		"TransTimes=00:00;14:05",
		"TransInterval=1",
		"ErrorDelay=60",
		"Delay=10",
		"Realtime=1",
	}
	return strings.Join(lines, "\n")
}
