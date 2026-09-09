package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cansarihan/reliquary/internal/cvss"
	"github.com/cansarihan/reliquary/internal/engine"
	"github.com/cansarihan/reliquary/internal/module"
	"github.com/cansarihan/reliquary/internal/risk"
)

func TestBuildAndEncode(t *testing.T) {
	project := module.Project{
		Main: "github.com/example/app",
		Modules: []module.Module{
			{Path: "golang.org/x/net", Version: "v0.15.0"},
			{Path: "github.com/a/b", Version: "v1.2.0", Indirect: true},
		},
	}
	reports := []engine.ModuleReport{{
		Path:    "golang.org/x/net",
		Version: "v0.15.0",
		Findings: []risk.Finding{{
			ID: "GO-2023-0001", CVE: "CVE-2023-1", Level: cvss.High, Score: 7.5,
		}},
	}}

	document := Build(project, reports)
	if document.Format != "CycloneDX" || document.SpecVersion != "1.5" {
		t.Errorf("header wrong: %+v", document.Metadata)
	}
	if !strings.HasPrefix(document.Serial, "urn:uuid:") {
		t.Errorf("serial = %q", document.Serial)
	}
	if len(document.Components) != 2 {
		t.Fatalf("want 2 components, got %d", len(document.Components))
	}
	if document.Components[0].PURL != "pkg:golang/golang.org/x/net@v0.15.0" {
		t.Errorf("purl = %q", document.Components[0].PURL)
	}
	if len(document.Vulns) != 1 || document.Vulns[0].Affects[0].Ref != "pkg:golang/golang.org/x/net@v0.15.0" {
		t.Errorf("vulnerability ref wrong: %+v", document.Vulns)
	}

	var buffer bytes.Buffer
	if err := Write(&buffer, document); err != nil {
		t.Fatalf("write: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &roundtrip); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if roundtrip["bomFormat"] != "CycloneDX" {
		t.Errorf("decoded bomFormat = %v", roundtrip["bomFormat"])
	}
}
