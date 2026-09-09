package risk

import (
	"encoding/json"
	"testing"

	"github.com/cansarihan/reliquary/internal/cvss"
	"github.com/cansarihan/reliquary/internal/osv"
)

func TestAssessFromVector(t *testing.T) {
	vuln := osv.Vuln{
		ID:      "GO-2023-0001",
		Summary: "critical remote code execution",
		Aliases: []string{"CVE-2023-1"},
		Severity: []osv.Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []osv.Affected{{
			Package: osv.Package{Name: "example.com/x"},
			Ranges:  []osv.Range{{Events: []osv.Event{{Fixed: "1.2.3"}}}},
		}},
	}
	finding := Assess(vuln, "example.com/x")
	if finding.Level != cvss.Critical {
		t.Errorf("level = %s, want critical", finding.Level)
	}
	if finding.Score < 9.7 {
		t.Errorf("score = %.1f, want ~9.8", finding.Score)
	}
	if finding.Fixed != "1.2.3" {
		t.Errorf("fixed = %q", finding.Fixed)
	}
	if finding.CVE != "CVE-2023-1" {
		t.Errorf("cve = %q", finding.CVE)
	}
}

func TestAssessFallsBackToQualitative(t *testing.T) {
	vuln := osv.Vuln{
		ID:               "GHSA-xxxx",
		Summary:          "high severity issue",
		DatabaseSpecific: json.RawMessage(`{"severity":"HIGH"}`),
	}
	finding := Assess(vuln, "example.com/y")
	if finding.Level != cvss.High {
		t.Errorf("level = %s, want high", finding.Level)
	}
	if finding.Score != 0 {
		t.Errorf("score = %.1f, want 0 without a vector", finding.Score)
	}
}

func TestAssessUnknownWhenNoData(t *testing.T) {
	finding := Assess(osv.Vuln{ID: "X"}, "p")
	if finding.Level != cvss.Unknown {
		t.Errorf("level = %s, want unknown", finding.Level)
	}
}

func TestMergePrefersHigherSeverityAndKeepsFix(t *testing.T) {
	scored := Finding{ID: "CVE-1", CVE: "CVE-1", Level: cvss.High, Score: 7.5, Fixed: ""}
	labelled := Finding{ID: "GO-1", CVE: "CVE-1", Level: cvss.Unknown, Score: 0, Fixed: "1.2.3", Summary: "detail"}

	merged := Merge(scored, labelled)
	if merged.Level != cvss.High || merged.Score != 7.5 {
		t.Errorf("merge should keep the scored severity: %+v", merged)
	}
	if merged.Fixed != "1.2.3" {
		t.Errorf("merge should adopt the fixed version from the other record: %+v", merged)
	}
}

func TestWorstAndTopScore(t *testing.T) {
	findings := []Finding{
		{Level: cvss.Low, Score: 3.1},
		{Level: cvss.Critical, Score: 9.8},
		{Level: cvss.Medium, Score: 5.3},
	}
	if Worst(findings) != cvss.Critical {
		t.Errorf("worst = %s", Worst(findings))
	}
	if TopScore(findings) != 9.8 {
		t.Errorf("top score = %.1f", TopScore(findings))
	}
	if Worst(nil) != cvss.None {
		t.Errorf("worst of nil should be none")
	}
}

func TestSummarizeTruncates(t *testing.T) {
	long := ""
	for i := 0; i < 40; i++ {
		long += "word "
	}
	vuln := osv.Vuln{Summary: long}
	finding := Assess(vuln, "p")
	if len([]rune(finding.Summary)) > 141 {
		t.Errorf("summary not truncated: %d runes", len([]rune(finding.Summary)))
	}
}

func TestIndexAndBand(t *testing.T) {
	counts := map[cvss.Level]int{cvss.Critical: 1, cvss.Low: 2}
	if index := Index(counts); index != 51 {
		t.Errorf("index = %d, want 51", index)
	}
	if Band(cvss.Critical) != "critical" {
		t.Errorf("band = %s", Band(cvss.Critical))
	}
	if Band(cvss.None) != "clean" {
		t.Errorf("band = %s", Band(cvss.None))
	}
}
