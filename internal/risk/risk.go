package risk

import (
	"encoding/json"
	"strings"

	"github.com/cansarihan/reliquary/internal/cvss"
	"github.com/cansarihan/reliquary/internal/osv"
)

type Finding struct {
	ID      string     `json:"id"`
	CVE     string     `json:"cve"`
	Summary string     `json:"summary"`
	Level   cvss.Level `json:"level"`
	Score   float64    `json:"score"`
	Fixed   string     `json:"fixed,omitempty"`
}

func Assess(vuln osv.Vuln, path string) Finding {
	finding := Finding{
		ID:      vuln.ID,
		CVE:     osv.CVE(vuln),
		Summary: summarize(vuln),
		Level:   cvss.Unknown,
		Fixed:   osv.FixedVersion(vuln, path),
	}

	if vector := osv.Vector(vuln); vector != "" {
		if score, ok := cvss.Score(vector); ok {
			finding.Score = score
			finding.Level = cvss.Classify(score)
			return finding
		}
	}
	if level := qualitative(vuln); level != cvss.Unknown {
		finding.Level = level
	}
	return finding
}

func Merge(a, b Finding) Finding {
	best := a
	if cvss.Rank(b.Level) > cvss.Rank(a.Level) || (cvss.Rank(b.Level) == cvss.Rank(a.Level) && b.Score > a.Score) {
		best = b
	}
	other := a
	if best == a {
		other = b
	}
	if best.Fixed == "" {
		best.Fixed = other.Fixed
	}
	if best.Summary == "" {
		best.Summary = other.Summary
	}
	return best
}

func Worst(findings []Finding) cvss.Level {
	worst := cvss.None
	for _, finding := range findings {
		if cvss.Rank(finding.Level) > cvss.Rank(worst) {
			worst = finding.Level
		}
	}
	return worst
}

func TopScore(findings []Finding) float64 {
	top := 0.0
	for _, finding := range findings {
		if finding.Score > top {
			top = finding.Score
		}
	}
	return top
}

var weights = map[cvss.Level]int{
	cvss.Critical: 45,
	cvss.High:     22,
	cvss.Medium:   9,
	cvss.Low:      3,
	cvss.Unknown:  3,
}

func Index(counts map[cvss.Level]int) int {
	total := 0
	for level, count := range counts {
		total += weights[level] * count
	}
	if total > 100 {
		total = 100
	}
	return total
}

func Band(worst cvss.Level) string {
	switch worst {
	case cvss.Critical:
		return "critical"
	case cvss.High:
		return "high"
	case cvss.Medium:
		return "elevated"
	case cvss.Low, cvss.Unknown:
		return "low"
	default:
		return "clean"
	}
}

func summarize(vuln osv.Vuln) string {
	text := strings.TrimSpace(vuln.Summary)
	if text == "" {
		text = strings.TrimSpace(vuln.Details)
	}
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		text = text[:index]
	}
	if len(text) > 140 {
		text = strings.TrimSpace(text[:140]) + "…"
	}
	return text
}

func qualitative(vuln osv.Vuln) cvss.Level {
	if len(vuln.DatabaseSpecific) == 0 {
		return cvss.Unknown
	}
	var specific struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(vuln.DatabaseSpecific, &specific); err != nil {
		return cvss.Unknown
	}
	switch strings.ToUpper(strings.TrimSpace(specific.Severity)) {
	case "CRITICAL":
		return cvss.Critical
	case "HIGH":
		return cvss.High
	case "MODERATE", "MEDIUM":
		return cvss.Medium
	case "LOW":
		return cvss.Low
	default:
		return cvss.Unknown
	}
}
