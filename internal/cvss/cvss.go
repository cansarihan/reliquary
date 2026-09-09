package cvss

import (
	"math"
	"strings"
)

type Level string

const (
	None     Level = "none"
	Unknown  Level = "unknown"
	Low      Level = "low"
	Medium   Level = "medium"
	High     Level = "high"
	Critical Level = "critical"
)

func Score(vector string) (float64, bool) {
	metrics := parse(vector)
	if metrics == nil {
		return 0, false
	}

	av, ok := lookup(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := lookup(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	ui, ok := lookup(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	scopeChanged := metrics["S"] == "C"
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok := lookup(metrics, "PR", prTable)
	if !ok {
		return 0, false
	}

	impactWeights := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}
	c, ok := lookup(metrics, "C", impactWeights)
	if !ok {
		return 0, false
	}
	i, ok := lookup(metrics, "I", impactWeights)
	if !ok {
		return 0, false
	}
	a, ok := lookup(metrics, "A", impactWeights)
	if !ok {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability
	if scopeChanged {
		base = 1.08 * base
	}
	return roundUp(math.Min(base, 10)), true
}

func Classify(score float64) Level {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return None
	}
}

func Rank(level Level) int {
	switch level {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Unknown:
		return 1
	default:
		return 0
	}
}

func parse(vector string) map[string]string {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return nil
	}
	fields := strings.Split(vector, "/")
	metrics := map[string]string{}
	for _, field := range fields {
		pair := strings.SplitN(field, ":", 2)
		if len(pair) != 2 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(pair[0]))
		if key == "CVSS" {
			continue
		}
		metrics[key] = strings.ToUpper(strings.TrimSpace(pair[1]))
	}
	if len(metrics) == 0 {
		return nil
	}
	return metrics
}

func lookup(metrics map[string]string, key string, table map[string]float64) (float64, bool) {
	value, ok := metrics[key]
	if !ok {
		return 0, false
	}
	weight, ok := table[value]
	return weight, ok
}

func roundUp(value float64) float64 {
	scaled := value * 100000
	rounded := math.Ceil(scaled / 10000)
	return rounded / 10
}
