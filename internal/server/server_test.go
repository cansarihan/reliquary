package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cansarihan/reliquary/internal/osv"
)

type fakeClient map[string][]osv.Vuln

func (f fakeClient) Query(_ context.Context, targets []osv.Target) (map[string][]osv.Vuln, error) {
	out := map[string][]osv.Vuln{}
	for _, target := range targets {
		if vulns, ok := f[target.Key()]; ok {
			out[target.Key()] = vulns
		}
	}
	return out, nil
}

func projectDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := "module github.com/example/app\n\ngo 1.25.0\n\nrequire golang.org/x/net v0.15.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestHealthz(t *testing.T) {
	handler := New(Options{UI: false}, BuildInfo{}).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("healthz = %d", recorder.Code)
	}
}

func TestGuard(t *testing.T) {
	handler := New(Options{Token: "secret", UI: false}, BuildInfo{}).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", recorder.Code)
	}
}

func TestCreateRejectsMissingModule(t *testing.T) {
	handler := New(Options{Dir: t.TempDir(), UI: false}, BuildInfo{}).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/scans", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without go.mod, got %d", recorder.Code)
	}
}

func TestCreateRunsScan(t *testing.T) {
	client := fakeClient{
		"golang.org/x/net@v0.15.0": {{
			ID:      "GO-2023-0001",
			Summary: "critical rce",
			Severity: []osv.Severity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
		}},
	}
	server := New(Options{Dir: projectDir(t), UI: false, Client: client}, BuildInfo{Version: "test"})
	handler := server.Handler()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/scans", nil))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("create = %d", recorder.Code)
	}
	var created Scan
	_ = json.Unmarshal(recorder.Body.Bytes(), &created)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got := httptest.NewRecorder()
		handler.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+created.ID, nil))
		var scan Scan
		_ = json.Unmarshal(got.Body.Bytes(), &scan)
		if scan.Status == "done" {
			if scan.Vulnerable != 1 || scan.Band != "critical" {
				t.Fatalf("scan result wrong: %+v", scan)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("scan did not finish in time")
}
