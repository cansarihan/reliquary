package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cansarihan/reliquary/internal/engine"
)

func JSON(w io.Writer, summary engine.Summary) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func Table(w io.Writer, summary engine.Summary) {
	duration := summary.Finished.Sub(summary.Started).Round(time.Millisecond)
	fmt.Fprintf(w, "%s\n", summary.Main)
	fmt.Fprintf(w, "%d modules scanned in %s\n", summary.Total, duration)
	fmt.Fprintf(w, "risk %s  ·  %d finding(s) in %d module(s)  ·  %s\n\n",
		summary.Band, summary.Findings, summary.Vulnerable, counts(summary))

	if summary.Vulnerable == 0 {
		fmt.Fprintln(w, "no known vulnerabilities")
		return
	}

	writer := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "SEVERITY\tCVSS\tADVISORY\tMODULE\tFIXED\tSUMMARY")
	for _, module := range summary.Modules {
		for _, finding := range module.Findings {
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n",
				finding.Level, score(finding.Score), finding.CVE,
				short(module.Path)+" "+module.Version, fixed(finding.Fixed), finding.Summary)
		}
	}
	_ = writer.Flush()
}

func counts(summary engine.Summary) string {
	var parts []string
	for _, level := range []string{"critical", "high", "medium", "low", "unknown"} {
		if count := summary.Counts[level]; count > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", level, count))
		}
	}
	if len(parts) == 0 {
		return "clean"
	}
	return strings.Join(parts, "  ")
}

func score(value float64) string {
	if value <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f", value)
}

func fixed(version string) string {
	if version == "" {
		return "-"
	}
	return version
}

func short(path string) string {
	if len(path) <= 34 {
		return path
	}
	return "…" + path[len(path)-33:]
}
