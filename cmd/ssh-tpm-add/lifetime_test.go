package main

import "testing"

func TestParseLifetime(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint32
	}{
		{"300", 300},
		{"5m", 300},
		{"1h30m", 5400},
		{"1d", 86400},
		{"1W2D3H", 788400},
		{"1.5s", 1},
		{".5", 0},
		{"0", 0},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := parseLifetime(tc.value)
			if err != nil || got != tc.want {
				t.Fatalf("parseLifetime(%q) = %d, %v; want %d", tc.value, got, err, tc.want)
			}
		})
	}

	for _, value := range []string{"", "-1", "1.5m", "1.s", "1x", "1s2s", "4294967296", "4294967295s1s"} {
		t.Run("invalid "+value, func(t *testing.T) {
			if _, err := parseLifetime(value); err == nil {
				t.Fatalf("parseLifetime(%q) unexpectedly succeeded", value)
			}
		})
	}
}
