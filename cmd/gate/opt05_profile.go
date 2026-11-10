package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
)

// startOpt05CPUProfile profiles command execution, after package initialization.
// The default rate is 100 Hz. Go 1.26.8 StartCPUProfile hardcodes 100 Hz;
// pre-setting a different rate retains that rate and emits the runtime warning
// "cannot set cpu profile rate until previous profile has finished". The rate
// stored in the resulting protobuf must be checked by the collector.
func startOpt05CPUProfile() (func(), error) {
	path := os.Getenv("OPT05_CPU_PROFILE")
	if path == "" {
		return func() {}, nil
	}
	hz := 100
	if value := os.Getenv("OPT05_CPU_HZ"); value != "" {
		var err error
		hz, err = strconv.Atoi(value)
		if err != nil || hz < 1 || hz > 500 {
			return nil, fmt.Errorf("opt05 cpu rate must be between 1 and 500 Hz")
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating opt05 cpu profile: %w", err)
	}
	if hz != 100 {
		runtime.SetCPUProfileRate(hz)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		runtime.SetCPUProfileRate(0)
		file.Close()
		return nil, fmt.Errorf("starting opt05 cpu profile: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { pprof.StopCPUProfile(); file.Close() }) }, nil
}
