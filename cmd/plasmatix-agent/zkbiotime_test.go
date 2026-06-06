package main

import (
	"reflect"
	"testing"
)

func TestAtoiPtr(t *testing.T) {
	cases := []struct {
		in string
		n  int
		ok bool
	}{
		{"1", 1, true},
		{" 2 ", 2, true},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, c := range cases {
		n, ok := atoiPtr(c.in)
		if n != c.n || ok != c.ok {
			t.Errorf("atoiPtr(%q) = (%d,%v), want (%d,%v)", c.in, n, ok, c.n, c.ok)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 3); got != "hel" {
		t.Errorf("truncate cut = %q", got)
	}
	if got := truncate("hi", 5); got != "hi" {
		t.Errorf("truncate short = %q", got)
	}
}

func TestEmployeeBody(t *testing.T) {
	row := map[string]string{
		"emp_code":   "6",
		"first_name": "A",
		"last_name":  "B",
		"department": "3",
		"area":       "2",
		"position":   "5",
		"gender":     "M",
		"birthday":   "",
		"email":      "a@b.c",
	}
	got := employeeBody(row)
	want := map[string]any{
		"emp_code":   "6",
		"first_name": "A",
		"last_name":  "B",
		"department": 3,
		"area":       []int{2},
		"position":   5,
		"gender":     "M",
		"email":      "a@b.c",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("employeeBody mismatch:\n got=%#v\nwant=%#v", got, want)
	}
	// empty birthday must be omitted
	if _, ok := got["birthday"]; ok {
		t.Errorf("empty birthday should be omitted")
	}
}

func TestEmployeeBodyOmitsMissingIDs(t *testing.T) {
	got := employeeBody(map[string]string{"emp_code": "9", "first_name": "X", "last_name": "Y"})
	for _, k := range []string{"department", "area", "position"} {
		if _, ok := got[k]; ok {
			t.Errorf("expected %q omitted when unset", k)
		}
	}
}
