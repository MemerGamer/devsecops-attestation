package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpt05Profile(t *testing.T) {
	t.Setenv("OPT05_CPU_PROFILE", "")
	stop, err := startOpt05CPUProfile()
	if err != nil {
		t.Fatal(err)
	}
	stop()
	path := filepath.Join(t.TempDir(), "cpu.pb.gz")
	t.Setenv("OPT05_CPU_PROFILE", path)
	t.Setenv("OPT05_CPU_HZ", "invalid")
	if _, err := startOpt05CPUProfile(); err == nil {
		t.Fatal("accepted invalid rate")
	}
	t.Setenv("OPT05_CPU_HZ", "100")
	stop, err = startOpt05CPUProfile()
	if err != nil {
		t.Fatal(err)
	}
	stop()
	stop()
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		t.Fatal("missing gzip profile", err)
	}
	if _, err := startOpt05CPUProfile(); err == nil {
		t.Fatal("overwrote profile")
	}
}
