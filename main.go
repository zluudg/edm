package main

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/dnstapir/edm/cmd"
)

// version set at build time with -ldflags="-X main.version=v0.0.1"
var version = "undefined"

func main() {
	defaultHostname := "edm-hostname-unknown"
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to get hostname, using '%s'", defaultHostname)
		hostname = defaultHostname
	}

	loggerLevel := new(slog.LevelVar) // Info by default

	// Logger used for all output
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: loggerLevel}))
	logger = logger.With("service", "edm")
	logger = logger.With("hostname", hostname)
	logger = logger.With("go_version", runtime.Version())
	logger = logger.With("version", version)

	// This makes any calls to the standard "log" package to use slog as
	// well
	slog.SetDefault(logger)

	cmd.Execute(logger, loggerLevel)
}
