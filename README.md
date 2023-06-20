# dta: dnstap(ir) anonymizer
## About
Tool for reading dnstap data, anonymizing IP addresses and potentially sampling
1-out-of-N messages from the input stream if requested.

Currently expects to read dnstap from a unix socket and can write the
anonymized output to either JSON-formatted text or raw framestream data that
can be read by other dnstap tools.
```
dta --help
Usage of /usr/local/bin/dta:
  -config string
    	config file for sensitive information (default "dta.toml")
  -cryptopan-key string
    	override the secret used for Crypto-PAn anonymization
  -cryptopan-key-salt string
    	the salt used for key derivation (default "dta-kdf-salt-val")
  -debug
    	print debug logging during operation
  -file-format string
    	output format ('json' or 'fstrm') (default "json")
  -output-filename string
    	the filename to write dnstap streams to (empty or '-' means stdout)
  -simple-random-sampling-n int
    	only capture random 1-out-of-N dnstap messages, 0 disables sampling
  -unix-socket-path string
    	the unix socket we create for dnstap senders (default "/var/lib/unbound/dnstap.sock")
```

## Usage
Using the tool requires the creation of a TOML config file for holding the
crypto-PAn secret (by default the config is read from the current working directory)

Basic usage, writing anonymized json data to `stdout`:
```
echo 'cryptopan-key = "mysecret"' > dta.toml
dta -unix-socket-path /opt/unbound/dnstap.sock
```
... writing `fstrm` data instead, only sampling 1-out-of-10 dnstap messages and
using a custom configuration file:
```
dta -unix-socket-path /opt/unbound/dnstap.sock -file-format fstrm -simple-random-sampling-n 10 -config /etc/my-custom-dta.toml
```

## Development
### Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:
* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
