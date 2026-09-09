package cvss

import (
	"math"
	"testing"
)

func TestScoreKnownVectors(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		level  Level
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Critical},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, High},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, High},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, Medium},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, Medium},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, Low},
	}
	for _, tc := range cases {
		got, ok := Score(tc.vector)
		if !ok {
			t.Errorf("Score(%q) not parsed", tc.vector)
			continue
		}
		if math.Abs(got-tc.want) > 0.01 {
			t.Errorf("Score(%q) = %.1f, want %.1f", tc.vector, got, tc.want)
		}
		if Classify(got) != tc.level {
			t.Errorf("Classify(%.1f) = %s, want %s", got, Classify(got), tc.level)
		}
	}
}

func TestScoreRejectsGarbage(t *testing.T) {
	for _, vector := range []string{"", "not-a-vector", "CVSS:3.1/AV:X/AC:L"} {
		if _, ok := Score(vector); ok {
			t.Errorf("Score(%q) should have failed", vector)
		}
	}
}

func TestRankOrder(t *testing.T) {
	order := []Level{None, Unknown, Low, Medium, High, Critical}
	for i := 1; i < len(order); i++ {
		if Rank(order[i]) <= Rank(order[i-1]) {
			t.Fatalf("rank not increasing at %s", order[i])
		}
	}
}
