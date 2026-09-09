package engine

import (
	"context"
	"testing"

	"github.com/cansarihan/reliquary/internal/module"
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

func TestRunGradesModules(t *testing.T) {
	project := module.Project{
		Main: "github.com/example/app",
		Modules: []module.Module{
			{Path: "golang.org/x/net", Version: "v0.15.0"},
			{Path: "github.com/clean/pkg", Version: "v1.0.0"},
			{Path: "example.com/local", Version: "", Local: true},
		},
	}
	client := fakeClient{
		"golang.org/x/net@v0.15.0": {{
			ID:      "GO-2023-0001",
			Summary: "critical rce",
			Severity: []osv.Severity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
			Affected: []osv.Affected{{
				Package: osv.Package{Name: "golang.org/x/net"},
				Ranges:  []osv.Range{{Events: []osv.Event{{Fixed: "0.17.0"}}}},
			}},
		}},
	}

	var moduleUpdates int
	summary, err := Run(context.Background(), project, client, func(update Update) {
		if update.Type == UpdateModule {
			moduleUpdates++
		}
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if summary.Total != 3 || summary.Vulnerable != 1 || summary.Findings != 1 {
		t.Fatalf("summary totals wrong: %+v", summary)
	}
	if summary.Worst != "critical" || summary.Band != "critical" {
		t.Errorf("worst=%s band=%s", summary.Worst, summary.Band)
	}
	if summary.Counts["critical"] != 1 {
		t.Errorf("counts = %+v", summary.Counts)
	}
	if moduleUpdates != 3 {
		t.Errorf("want 3 module updates, got %d", moduleUpdates)
	}
	if summary.Modules[0].Path != "golang.org/x/net" {
		t.Errorf("vulnerable module should sort first, got %q", summary.Modules[0].Path)
	}
	if summary.Modules[0].Worst != "critical" {
		t.Errorf("worst level lost: %+v", summary.Modules[0])
	}
}

func TestRunCleanProject(t *testing.T) {
	project := module.Project{
		Main:    "github.com/example/clean",
		Modules: []module.Module{{Path: "github.com/a/b", Version: "v1.0.0"}},
	}
	summary, err := Run(context.Background(), project, fakeClient{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Vulnerable != 0 || summary.Band != "clean" {
		t.Errorf("clean project summary wrong: %+v", summary)
	}
}
