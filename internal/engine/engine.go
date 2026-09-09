package engine

import (
	"context"
	"sort"
	"time"

	"github.com/cansarihan/reliquary/internal/cvss"
	"github.com/cansarihan/reliquary/internal/module"
	"github.com/cansarihan/reliquary/internal/osv"
	"github.com/cansarihan/reliquary/internal/risk"
)

type UpdateType string

const (
	UpdateModule   UpdateType = "module"
	UpdateProgress UpdateType = "progress"
)

type Update struct {
	Type   UpdateType    `json:"type"`
	Module *ModuleReport `json:"module,omitempty"`
	Done   int           `json:"done,omitempty"`
	Total  int           `json:"total,omitempty"`
}

type ModuleReport struct {
	Path     string         `json:"path"`
	Version  string         `json:"version"`
	Indirect bool           `json:"indirect"`
	Local    bool           `json:"local,omitempty"`
	Worst    cvss.Level     `json:"worst"`
	Score    float64        `json:"score"`
	Findings []risk.Finding `json:"findings,omitempty"`
}

type Summary struct {
	Main       string         `json:"main"`
	GoVersion  string         `json:"go_version"`
	Started    time.Time      `json:"started"`
	Finished   time.Time      `json:"finished"`
	Total      int            `json:"total"`
	Vulnerable int            `json:"vulnerable"`
	Findings   int            `json:"findings"`
	Counts     map[string]int `json:"counts"`
	Worst      string         `json:"worst"`
	Index      int            `json:"index"`
	Band       string         `json:"band"`
	Modules    []ModuleReport `json:"modules"`
}

func Run(ctx context.Context, project module.Project, client osv.Client, emit func(Update)) (Summary, error) {
	if emit == nil {
		emit = func(Update) {}
	}
	summary := Summary{
		Main:      project.Main,
		GoVersion: project.GoVersion,
		Started:   time.Now(),
		Total:     len(project.Modules),
		Counts:    map[string]int{},
	}

	var targets []osv.Target
	for _, mod := range project.Modules {
		if mod.Local || mod.Version == "" {
			continue
		}
		targets = append(targets, osv.Target{Path: mod.Path, Version: mod.Version})
	}

	vulns, err := client.Query(ctx, targets)
	if err != nil {
		return summary, err
	}

	levelCounts := map[cvss.Level]int{}
	reports := make([]ModuleReport, 0, len(project.Modules))
	for index, mod := range project.Modules {
		report := ModuleReport{
			Path:     mod.Path,
			Version:  mod.Version,
			Indirect: mod.Indirect,
			Local:    mod.Local,
			Worst:    cvss.None,
		}
		seen := map[string]int{}
		for _, vuln := range vulns[mod.Key()] {
			finding := risk.Assess(vuln, mod.Path)
			if position, ok := seen[finding.CVE]; ok {
				report.Findings[position] = risk.Merge(report.Findings[position], finding)
				continue
			}
			seen[finding.CVE] = len(report.Findings)
			report.Findings = append(report.Findings, finding)
		}
		for _, finding := range report.Findings {
			levelCounts[finding.Level]++
			summary.Counts[string(finding.Level)]++
			summary.Findings++
		}
		if len(report.Findings) > 0 {
			sort.Slice(report.Findings, func(i, j int) bool {
				return cvss.Rank(report.Findings[i].Level) > cvss.Rank(report.Findings[j].Level)
			})
			report.Worst = risk.Worst(report.Findings)
			report.Score = risk.TopScore(report.Findings)
			summary.Vulnerable++
		}
		reports = append(reports, report)

		copied := report
		emit(Update{Type: UpdateModule, Module: &copied})
		emit(Update{Type: UpdateProgress, Done: index + 1, Total: len(project.Modules)})
	}

	sort.Slice(reports, func(i, j int) bool {
		if cvss.Rank(reports[i].Worst) != cvss.Rank(reports[j].Worst) {
			return cvss.Rank(reports[i].Worst) > cvss.Rank(reports[j].Worst)
		}
		if reports[i].Score != reports[j].Score {
			return reports[i].Score > reports[j].Score
		}
		return reports[i].Path < reports[j].Path
	})

	summary.Modules = reports
	summary.Worst = string(worstLevel(levelCounts))
	summary.Index = risk.Index(levelCounts)
	summary.Band = risk.Band(worstLevel(levelCounts))
	summary.Finished = time.Now()
	return summary, nil
}

func worstLevel(counts map[cvss.Level]int) cvss.Level {
	worst := cvss.None
	for level, count := range counts {
		if count > 0 && cvss.Rank(level) > cvss.Rank(worst) {
			worst = level
		}
	}
	return worst
}
