package module

import (
	"os"
	"path/filepath"
	"testing"
)

const fixture = `module github.com/example/app

go 1.25.0

require (
	golang.org/x/net v0.17.0
	github.com/gin-gonic/gin v1.9.0
)

require github.com/rogpeppe/go-internal v1.9.0 // indirect

replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.1
`

func TestParse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	project, err := Parse(dir)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if project.Main != "github.com/example/app" {
		t.Errorf("main = %q", project.Main)
	}
	if project.GoVersion != "1.25.0" {
		t.Errorf("go version = %q", project.GoVersion)
	}
	if len(project.Modules) != 3 {
		t.Fatalf("want 3 modules, got %d: %+v", len(project.Modules), project.Modules)
	}
	if len(project.Direct) != 2 {
		t.Errorf("want 2 direct modules, got %v", project.Direct)
	}

	byPath := map[string]Module{}
	for _, mod := range project.Modules {
		byPath[mod.Path] = mod
	}
	if gin := byPath["github.com/gin-gonic/gin"]; gin.Version != "v1.9.1" {
		t.Errorf("replace not applied: %+v", gin)
	}
	if internal := byPath["github.com/rogpeppe/go-internal"]; !internal.Indirect {
		t.Errorf("indirect flag lost: %+v", internal)
	}
}

func TestParseMissing(t *testing.T) {
	if _, err := Parse(t.TempDir()); err == nil {
		t.Fatal("expected error when go.mod is absent")
	}
}
