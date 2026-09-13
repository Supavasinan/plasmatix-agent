package main

import "testing"

func TestBuildUserInfoCommandMatchesZKBioTimeFieldOrder(t *testing.T) {
	got, err := buildUserInfoCommand(deviceUser{pin: "21", name: "Somchai"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "DATA UPDATE USERINFO PIN=21\tName=Somchai\tPasswd=\tCard=\tPri=0\tVerify=-1"
	if got != want {
		t.Fatalf("command mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestBuildUserInfoCommandKeepsCallerValues(t *testing.T) {
	got, err := buildUserInfoCommand(deviceUser{
		pin: "7", name: "Admin", passwd: "1234", card: "998877", pri: "14", verify: "1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "DATA UPDATE USERINFO PIN=7\tName=Admin\tPasswd=1234\tCard=998877\tPri=14\tVerify=1"
	if got != want {
		t.Fatalf("command mismatch:\n got %q\nwant %q", got, want)
	}
}

// A tab inside a name would shift Passwd into Name's slot and every field after
// it by one, storing a mangled user instead of failing.
func TestBuildUserInfoCommandCollapsesDelimitersInValues(t *testing.T) {
	got, err := buildUserInfoCommand(deviceUser{pin: " 9 ", name: "A\tB\nC"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "DATA UPDATE USERINFO PIN=9\tName=A B C\tPasswd=\tCard=\tPri=0\tVerify=-1"
	if got != want {
		t.Fatalf("command mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestBuildUserInfoCommandRequiresPin(t *testing.T) {
	if _, err := buildUserInfoCommand(deviceUser{name: "No PIN"}); err == nil {
		t.Fatal("expected an error for an empty pin")
	}
}
