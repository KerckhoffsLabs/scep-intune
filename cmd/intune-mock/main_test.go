package main

import (
	"flag"
	"strings"
	"testing"
)

func TestApplyEnv(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "")
	maxRecords := fs.Int("max-records", 1000, "")
	env := map[string]string{"MOCK_BASE_URL": "https://m:8443", "MOCK_MAX_RECORDS": "7"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if err := applyEnv(fs, lookup); err != nil {
		t.Fatal(err)
	}
	if *baseURL != "https://m:8443" || *maxRecords != 7 {
		t.Fatalf("base-url=%q max-records=%d", *baseURL, *maxRecords)
	}
}

// An invalid value must stop the mock, not silently fall back to the default.
func TestApplyEnvRejectsInvalidValue(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.Int("max-records", 1000, "")
	lookup := func(k string) (string, bool) { return "abc", k == "MOCK_MAX_RECORDS" }
	err := applyEnv(fs, lookup)
	if err == nil || !strings.Contains(err.Error(), "MOCK_MAX_RECORDS") {
		t.Fatalf("err = %v, want an error naming MOCK_MAX_RECORDS", err)
	}
}
