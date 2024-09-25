package main

import "github.com/dnstapir/edm/cmd"

// version set at build time with -ldflags="-X main.version=v0.0.1"
var version = "undefined"

func main() {
	cmd.Execute(version)
}
