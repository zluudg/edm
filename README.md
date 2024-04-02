# dtm: dnstap(ir) minimiser
## About
Tool for reading dnstap data, pseudonymising IP addresses and outputting minimised output data.

Currently expects to read dnstap from a unix socket and writes out parquet
files for the collected information.

Requires a DAWG file for keeping track of well-known domains. Such a file can
be created using the tool available in
https://github.com/dnstapir/dtm-dawg-maker
```
Usage:
  dtm [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  run         Run dtm in dnstap capture mode

Flags:
      --config string   config file for sensitive information (default is $HOME/.dtm.yaml)
  -h, --help            help for dtm

Use "dtm [command] --help" for more information about a command.
```

## Usage
Using the tool requires the creation of a TOML config file for holding the
crypto-PAn secret (by default the config is read from the current working
 directory) as well as a `well-known-domains.dawg` file which can be created
using https://github.com/dnstapir/dtm-dawg-maker

Basic usage, writing output files to a directory structure under `/var/lib/dtm`
```
echo 'cryptopan-key = "mysecret"' > dtm.toml
dtm-dawg-maker
dtm run --input-unix /opt/unbound/dnstap.sock
```

## Development
### Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:
* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
