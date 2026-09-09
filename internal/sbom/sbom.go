package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/cansarihan/reliquary/internal/engine"
	"github.com/cansarihan/reliquary/internal/module"
)

type Document struct {
	Format      string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Serial      string          `json:"serialNumber"`
	Version     int             `json:"version"`
	Metadata    Metadata        `json:"metadata"`
	Components  []Component     `json:"components"`
	Vulns       []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []Tool     `json:"tools"`
	Component *Component `json:"component,omitempty"`
}

type Tool struct {
	Name string `json:"name"`
}

type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Ref     string `json:"bom-ref"`
	Scope   string `json:"scope,omitempty"`
}

type Vulnerability struct {
	ID      string   `json:"id"`
	Source  *Source  `json:"source,omitempty"`
	Ratings []Rating `json:"ratings,omitempty"`
	Affects []Affect `json:"affects"`
}

type Source struct {
	Name string `json:"name"`
}

type Rating struct {
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity"`
	Method   string  `json:"method,omitempty"`
}

type Affect struct {
	Ref string `json:"ref"`
}

func Build(project module.Project, reports []engine.ModuleReport) Document {
	document := Document{
		Format:      "CycloneDX",
		SpecVersion: "1.5",
		Serial:      "urn:uuid:" + uuid(),
		Version:     1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []Tool{{Name: "reliquary"}},
		},
	}
	if project.Main != "" {
		document.Metadata.Component = &Component{
			Type: "application",
			Name: project.Main,
			Ref:  purl(project.Main, ""),
		}
	}

	for _, mod := range project.Modules {
		scope := "required"
		if mod.Indirect {
			scope = "optional"
		}
		reference := purl(mod.Path, mod.Version)
		document.Components = append(document.Components, Component{
			Type:    "library",
			Name:    mod.Path,
			Version: mod.Version,
			PURL:    reference,
			Ref:     reference,
			Scope:   scope,
		})
	}

	for _, report := range reports {
		reference := purl(report.Path, report.Version)
		for _, finding := range report.Findings {
			vulnerability := Vulnerability{
				ID:      finding.ID,
				Source:  &Source{Name: "OSV"},
				Affects: []Affect{{Ref: reference}},
			}
			if finding.Score > 0 {
				vulnerability.Ratings = append(vulnerability.Ratings, Rating{
					Score:    finding.Score,
					Severity: string(finding.Level),
					Method:   "CVSSv3",
				})
			} else {
				vulnerability.Ratings = append(vulnerability.Ratings, Rating{Severity: string(finding.Level)})
			}
			document.Vulns = append(document.Vulns, vulnerability)
		}
	}
	return document
}

func Write(w io.Writer, document Document) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func purl(path, version string) string {
	if version == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
}

func uuid() string {
	buffer := make([]byte, 16)
	_, _ = rand.Read(buffer)
	buffer[6] = (buffer[6] & 0x0f) | 0x40
	buffer[8] = (buffer[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buffer[0:4], buffer[4:6], buffer[6:8], buffer[8:10], buffer[10:16])
}
