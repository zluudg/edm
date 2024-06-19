# edm: edge dnstap minimiser

## About

Tool for reading dnstap data, pseudonymising IP addresses and outputting minimised output data.

Currently expects to read dnstap from a unix socket and writes out parquet
files for the collected information.

Requires a DAWG file for keeping track of well-known domains. Such a file can
be created using the tool available in
<https://github.com/dnstapir/edm-dawg-maker>

```text
Usage:
  edm [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  run         Run edm in dnstap capture mode

Flags:
      --config string   config file for sensitive information (default is $HOME/.edm.yaml)
  -h, --help            help for edm

Use "edm [command] --help" for more information about a command.
```

## Usage

Using the tool requires the creation of a TOML config file for holding the
crypto-PAn secret (by default the config is read from the current working
 directory) as well as a `well-known-domains.dawg` file which can be created
using <https://github.com/dnstapir/edm-dawg-maker>

Basic usage, writing output files to a directory structure under `/var/lib/edm`

```text
echo 'cryptopan-key = "mysecret"' > edm.toml
edm-dawg-maker
edm run --input-unix /opt/unbound/dnstap.sock
```

## Development

### Formatting and linting

When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:

* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
* `golangci-lint run` (see [golangci-lint](https://golangci-lint.run))
* `go test ./...`
