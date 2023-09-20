# dtm: dnstap(ir) minimiser
## About
Tool for reading dnstap data, pseudonymizing IP addresses and potentially sampling
1-out-of-N messages from the input stream if requested.

Currently expects to read dnstap from a unix socket and can write the
pseudonymized output to either JSON-formatted text or raw framestream data that
can be read by other dnstap tools.
```
Usage of ./dtm:
  -config string
    	config file for sensitive information (default "dtm.toml")
  -cryptopan-key string
    	override the secret used for Crypto-PAn pseudonymization
  -cryptopan-key-salt string
    	the salt used for key derivation (default "dtm-kdf-salt-val")
  -debug
    	print debug logging during operation
  -file-format string
    	output format when writing to a file ('json' or 'fstrm') (default "json")
  -input-unix string
    	create unix socket for reading dnstap (default "/var/lib/unbound/dnstap.sock")
  -output-file string
    	the file to write dnstap streams to ('-' means stdout)
  -output-tcp string
    	the target and port to write dnstap streams to, e.g. '127.0.0.1:5555'
```

## Usage
Using the tool requires the creation of a TOML config file for holding the
crypto-PAn secret (by default the config is read from the current working directory)

Basic usage, writing pseudonymized json data to `stdout`:
```
echo 'cryptopan-key = "mysecret"' > dta.toml
dta -input-unix /opt/unbound/dnstap.sock -output-file -
```
... writing `fstrm` data instead, only sampling 1-out-of-10 dnstap messages and
using a custom configuration file:
```
dta -input-unix /opt/unbound/dnstap.sock -output-file - -file-format fstrm -simple-random-sampling-n 10 -config /etc/my-custom-dta.toml
```

## Development
### Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:
* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
