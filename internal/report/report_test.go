package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cansarihan/reliquary/internal/cvss"
	"github.com/cansarihan/reliquary/internal/engine"
	"github.com/cansarihan/reliquary/internal/risk"
)

func sample() engine.Summary {
	return engine.Summary{
		Main:       "github.com/example/app",
		Started:    time.Now().Add(-time.Second),
		Finished:   time.Now(),
		Total:      12,
		Vulnerable: 1,
		Findings:   1,
		Counts:     map[string]int{"high": 1},
		Worst:      "high",
		Band:       "high",
		Modules: []engine.ModuleReport{{
			Path: "golang.org/x/net", Version: "v0.15.0", Worst: cvss.High, Score: 7.5,
			Findings: []risk.Finding{{
				ID: "GO-2023-0001", CVE: "CVE-2023-1", Level: cvss.High, Score: 7.5,
				Fixed: "v0.17.0", Summary: "denial of service",
			}},
		}},
	}
}

func TestTable(t *testing.T) {
	var buffer bytes.Buffer
	Table(&buffer, sample())
	output := buffer.String()
	for _, want := range []string{"github.com/example/app", "high:1", "CVE-2023-1", "v0.17.0", "denial of service"} {
		if !strings.Contains(output, want) {
			t.Errorf("table missing %q\n%s", want, output)
		}
	}
}

func TestTableClean(t *testing.T) {
	var buffer bytes.Buffer
	Table(&buffer, engine.Summary{Main: "clean", Counts: map[string]int{}, Band: "clean"})
	if !strings.Contains(buffer.String(), "no known vulnerabilities") {
		t.Errorf("clean output = %s", buffer.String())
	}
}

func TestJSON(t *testing.T) {
	var buffer bytes.Buffer
	if err := JSON(&buffer, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "\"worst\": \"high\"") {
		t.Errorf("json missing worst: %s", buffer.String())
	}
}
