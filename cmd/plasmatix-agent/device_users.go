package main

import (
	"fmt"
	"strings"
)

// Building the ADMS command that puts a user on a scanner.
//
// The field list is not a style choice. This agent previously sent
//
//	DATA UPDATE USERINFO PIN=<pin>\tName=<name>\tCard=<card>
//
// and ZKBioTime's own production command log shows a comparable attempt with
// invented names (Privilege=, Password=, Group=, StartTime=, EndTime=) being
// answered by the firmware with Return=-629 and nothing else. The rejection is
// a field-name error, not a firmware limitation: extracting the string
// constants from a customer's installed ZKBioTime 8
// (mysite/iclock/devview_ex.pyc) shows it assembles the command from exactly
// these fragments, in exactly this order:
//
//	"DATA UPDATE USERINFO PIN=" "\tName=" "\tPasswd=" "\tCard=" "\tPri=" "\tVerify="
//
// So Card belongs after Passwd, not before it, and Pri and Verify are not
// optional trailing extras — a layout the device does not recognise is refused
// whole. Match ZKBioTime byte for byte and do not reorder.
type deviceUser struct {
	pin    string
	name   string
	passwd string
	card   string
	pri    string
	verify string
}

// ZKTeco privilege levels: 0 is an ordinary user, 14 a device administrator.
const devicePrivilegeUser = "0"

// Verify mode -1 means "use whatever the device is configured for". Sending a
// concrete mode would quietly override that person's verification method on
// the hardware, which is not something a name-and-PIN push should decide.
const deviceVerifyDefault = "-1"

// Fields are tab-delimited, so a tab or newline inside a value would split the
// record and shift every later field by one — yielding a corrupted user rather
// than a refused command, which is the harder failure to notice.
func sanitizeDeviceField(value string) string {
	return strings.TrimSpace(
		strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(value),
	)
}

func buildUserInfoCommand(user deviceUser) (string, error) {
	pin := sanitizeDeviceField(user.pin)
	if pin == "" {
		return "", fmt.Errorf("syncUser requires a pin")
	}

	pri := sanitizeDeviceField(user.pri)
	if pri == "" {
		pri = devicePrivilegeUser
	}
	verify := sanitizeDeviceField(user.verify)
	if verify == "" {
		verify = deviceVerifyDefault
	}

	return fmt.Sprintf(
		"DATA UPDATE USERINFO PIN=%s\tName=%s\tPasswd=%s\tCard=%s\tPri=%s\tVerify=%s",
		pin,
		sanitizeDeviceField(user.name),
		sanitizeDeviceField(user.passwd),
		sanitizeDeviceField(user.card),
		pri,
		verify,
	), nil
}
