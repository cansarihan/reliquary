package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryBatchesAndFetchesDetails(t *testing.T) {
	var batchCalls, vulnCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		batchCalls++
		var body struct {
			Queries []struct {
				Package Package `json:"package"`
				Version string  `json:"version"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		results := make([]map[string]any, len(body.Queries))
		for i, q := range body.Queries {
			if q.Package.Name == "golang.org/x/net" {
				results[i] = map[string]any{"vulns": []map[string]string{{"id": "GO-2023-0001"}}}
			} else {
				results[i] = map[string]any{}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		vulnCalls++
		_ = json.NewEncoder(w).Encode(Vuln{
			ID:       "GO-2023-0001",
			Summary:  "denial of service in x/net",
			Aliases:  []string{"CVE-2023-44487"},
			Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
			Affected: []Affected{{
				Package: Package{Name: "golang.org/x/net", Ecosystem: "Go"},
				Ranges:  []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.17.0"}}}},
			}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := New(server.Client())
	client.baseURL = server.URL

	targets := []Target{
		{Path: "golang.org/x/net", Version: "v0.15.0"},
		{Path: "github.com/clean/pkg", Version: "v1.0.0"},
	}
	result, err := client.Query(context.Background(), targets)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if batchCalls != 1 {
		t.Errorf("want a single batch call, got %d", batchCalls)
	}
	if vulnCalls != 1 {
		t.Errorf("want one detail fetch, got %d", vulnCalls)
	}

	vulns := result["golang.org/x/net@v0.15.0"]
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln for x/net, got %d", len(vulns))
	}
	if _, ok := result["github.com/clean/pkg@v1.0.0"]; ok {
		t.Error("clean package should have no entry")
	}
	if CVE(vulns[0]) != "CVE-2023-44487" {
		t.Errorf("CVE = %q", CVE(vulns[0]))
	}
	if FixedVersion(vulns[0], "golang.org/x/net") != "0.17.0" {
		t.Errorf("fixed = %q", FixedVersion(vulns[0], "golang.org/x/net"))
	}
	if Vector(vulns[0]) == "" {
		t.Error("expected a CVSS vector")
	}
}

func TestQueryEmpty(t *testing.T) {
	client := New(nil)
	result, err := client.Query(context.Background(), nil)
	if err != nil || len(result) != 0 {
		t.Fatalf("empty query = %v, %v", result, err)
	}
}
