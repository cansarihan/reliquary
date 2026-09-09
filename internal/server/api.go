package server

import (
	"time"

	"github.com/cansarihan/reliquary/internal/engine"
)

type Scan struct {
	ID         string                `json:"id"`
	Main       string                `json:"main"`
	Dir        string                `json:"dir"`
	Status     string                `json:"status"`
	Started    time.Time             `json:"started"`
	Finished   time.Time             `json:"finished,omitempty"`
	Done       int                   `json:"done"`
	Total      int                   `json:"total"`
	Vulnerable int                   `json:"vulnerable"`
	Findings   int                   `json:"findings"`
	Counts     map[string]int        `json:"counts"`
	Worst      string                `json:"worst"`
	Index      int                   `json:"index"`
	Band       string                `json:"band"`
	Error      string                `json:"error,omitempty"`
	Modules    []engine.ModuleReport `json:"modules"`
}

type Status struct {
	Version   string    `json:"version"`
	Commit    string    `json:"commit"`
	GoVersion string    `json:"go_version"`
	Platform  string    `json:"platform"`
	Dir       string    `json:"dir"`
	StartedAt time.Time `json:"started_at"`
	Uptime    string    `json:"uptime"`
	Scans     int       `json:"scans"`
	Running   int       `json:"running"`
}
