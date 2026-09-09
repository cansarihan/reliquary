package module

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/mod/modfile"
)

type Module struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
	Local    bool   `json:"local,omitempty"`
}

type Project struct {
	Main      string   `json:"main"`
	GoVersion string   `json:"go_version"`
	Dir       string   `json:"dir"`
	Modules   []Module `json:"modules"`
	Direct    []string `json:"direct"`
}

func (m Module) Key() string {
	return m.Path + "@" + m.Version
}

func Parse(dir string) (Project, error) {
	path := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return Project{}, fmt.Errorf("read go.mod: %w", err)
	}

	file, err := modfile.Parse(path, data, nil)
	if err != nil {
		return Project{}, fmt.Errorf("parse go.mod: %w", err)
	}

	project := Project{Dir: dir}
	if file.Module != nil {
		project.Main = file.Module.Mod.Path
	}
	if file.Go != nil {
		project.GoVersion = file.Go.Version
	}

	replacements := replacementMap(file)

	for _, require := range file.Require {
		module := Module{
			Path:     require.Mod.Path,
			Version:  require.Mod.Version,
			Indirect: require.Indirect,
		}
		if replacement, ok := replacements[require.Mod.Path]; ok {
			module.Path = replacement.Path
			module.Version = replacement.Version
			module.Local = replacement.Version == ""
		}
		project.Modules = append(project.Modules, module)
		if !require.Indirect {
			project.Direct = append(project.Direct, require.Mod.Path)
		}
	}

	sort.Slice(project.Modules, func(i, j int) bool {
		return project.Modules[i].Path < project.Modules[j].Path
	})
	sort.Strings(project.Direct)
	return project, nil
}

func replacementMap(file *modfile.File) map[string]struct {
	Path    string
	Version string
} {
	out := map[string]struct {
		Path    string
		Version string
	}{}
	for _, replace := range file.Replace {
		out[replace.Old.Path] = struct {
			Path    string
			Version string
		}{Path: replace.New.Path, Version: replace.New.Version}
	}
	return out
}
