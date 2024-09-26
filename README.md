# edm: Edge DNSTAP Minimiser

## About
`edm` reads DNSTAP and depending on configuration can output some different
data based on the observed messages:
* DNS queries for names considered well-known will be summarised into
histograms which are saved as parquet files. These files will then be submitted
to Core.
* DNS queries for names not considered well-known are collected into other
parquet files for further local analysis and here the complete message content
is saved but the client and server IP-addresses are pseudonymised via
[Crypto-PAn](https://en.wikipedia.org/wiki/Crypto-PAn).
* DNS queries that are not considered well-known and have never been seen
before by a given instance of `edm` will result in notifications beingsent to
Core via MQTT messages.

## Usage
Running `edm` requires the creation of a TOML config file for holding the
crypto-PAn secret used for pseudonymisation as well as a
`well-known-domains.dawg` file which can be created using
<https://github.com/dnstapir/tapir-cli>

### Steps for a basic local-only setup
A basic setup where `edm` will listen on a unix socket for DNSTAP data and
output files to a directory structure under `/tmp/edm` but not send anything to
Core can be created like this:
```text
echo 'cryptopan-key = "mysecret"' > edm.toml
curl -O https://www.domcop.com/files/top/top10milliondomains.csv.zip
unzip top10milliondomains.csv.zip
tapir-cli dawg --standalone compile --format csv --src top10milliondomains.csv --dawg well-known-domains.dawg
edm run --input-unix /tmp/edm/input.sock --data-dir /tmp/edm/data --config edm.toml --well-known-domains well-known-domains.dawg --disable-mqtt --disable-histogram-sender
```

Since all communication with Core is disabled this is helpful for creating some
local parquet files to look around in. For inspecting the content you can use
e.g. [DuckDB](https://duckdb.org) like so:
### For summarised histogram data
```text
duckdb -c 'select * from "/tmp/edm/data/parquet/histograms/outbox/dns_histogram-2024-09-26T18-14-00Z_2024-09-26T18-15-00Z.parquet"'
```
### For pseudonymised session (full message) data
```text
duckdb -c 'select * from "/tmp/edm/data/parquet/sessions/dns_session_block-2024-09-26T18-18-00Z_2024-09-26T18-19-00Z.parquet"'
```

Next to the parquet directory you will also see a directory called "pebble".
This is where `edm` keeps its key-value store which is used to tell if a
query name has been seen before or not. The key-value store being used is
[pebble](https://github.com/cockroachdb/pebble)

## Development

### Formatting and linting

When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:

* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
* `golangci-lint run` (see [golangci-lint](https://golangci-lint.run))
* `go test -race ./...`
