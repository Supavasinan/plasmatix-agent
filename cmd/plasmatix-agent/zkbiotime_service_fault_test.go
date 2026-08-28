package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// biotimeFaultPage is the exact body BioTime serves — with HTTP 200 — when the
// application behind Apache cannot service a request. Captured from the live
// server during the 2026-08-19 outage, where it reached the poll loop as
// "pull transactions after ID 1196: invalid character '<' looking for
// beginning of value" once a minute, for hours, with no hint of the cause.
const biotimeFaultPage = "\n<html>\n<head>\n<title>500 Error</title>\n</head>\n<body>\n" +
	"<h1>\"The operation you selected is not working properly or the service is not available!\"</h1>\n\n" +
	"</body>\n</html>\n"

func faultPageServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, biotimeFaultPage) // note: HTTP 200
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The read path must name the outage instead of surfacing a JSON parse error.
func TestFetchTransactionsAfterIDExplainsFaultPage(t *testing.T) {
	srv := faultPageServer(t)
	c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())

	_, err := c.fetchTransactionsAfterID(context.Background(), 1196)
	if err == nil {
		t.Fatal("expected an error when BioTime serves its fault page")
	}
	if strings.Contains(err.Error(), "invalid character") {
		t.Errorf("error still surfaces the raw JSON parse failure: %v", err)
	}
	if !strings.Contains(err.Error(), "service is down") {
		t.Errorf("error = %v, want it to name the service outage", err)
	}
}

// The write path is the dangerous one: every mutation checks only the status
// code, so a 200-with-HTML outage previously reported employees as created.
func TestUpsertEmployeeFailsOnFaultPageInsteadOfReportingSuccess(t *testing.T) {
	srv := faultPageServer(t)
	c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())

	created, err := c.upsertEmployee(context.Background(), map[string]string{"emp_code": "1001"})
	if err == nil {
		t.Fatal("expected an error; a fault page must never read as a successful push")
	}
	if created {
		t.Error("created = true for an employee BioTime never received")
	}
}

func TestResyncToDeviceFailsOnFaultPage(t *testing.T) {
	srv := faultPageServer(t)
	c := newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())

	if err := c.resyncToDevice(context.Background(), []string{"1001"}); err == nil {
		t.Fatal("expected an error when BioTime serves its fault page")
	}
}

// The API explorer is a debugging tool: it must keep showing the raw body,
// which is exactly what an operator needs to see during an outage.
func TestZkbiotimeRequestStillReturnsNonJSONBody(t *testing.T) {
	srv := faultPageServer(t)
	a := &Agent{zkbiotime: newZKBioTimeClientWith(srv.URL, "x", "x", srv.Client())}

	out, err := a.cmdZkbiotimeRequest(context.Background(), map[string]string{
		"method": "GET",
		"path":   "/iclock/api/transactions/",
	})
	if err != nil {
		t.Fatalf("the explorer must pass the response through, got error: %v", err)
	}
	result, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("result = %T, want map[string]any", out)
	}
	if result["status"] != http.StatusOK {
		t.Errorf("status = %v, want 200", result["status"])
	}
	body, _ := result["body"].(string)
	if !strings.Contains(body, "500 Error") {
		t.Errorf("body = %q, want the raw HTML passed through", body)
	}
}
