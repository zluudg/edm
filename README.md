# dtm: dnstap(ir) minimiser
## About
Tool for reading dnstap data, pseudonymizing IP addresses and outputting minimised output data.

Currently expects to read dnstap from a unix socket and writes out parquet
files for the collected information.

Requires a DAWG file for keeping track of well-known domains. Such a file can
be created using the tool available in
https://github.com/dnstapir/dtm-dawg-maker
```
Usage of dtm:
  -config string
    	config file for sensitive information (default "dtm.toml")
  -cryptopan-key string
    	override the secret used for Crypto-PAn pseudonymization
  -cryptopan-key-salt string
    	the salt used for key derivation (default "dtm-kdf-salt-val")
  -data-dir string
    	directory where output data is written (default "/var/lib/dtm")
  -debug
    	print debug logging during operation
  -input-unix string
    	create unix socket for reading dnstap (default "/var/lib/unbound/dnstap.sock")
  -mqtt-ca string
    	CA cert used for validating MQTT TLS connection (default "mqtt-ca.crt")
  -mqtt-clean-start
    	Control if a new MQTT session is created when connecting (default true)
  -mqtt-client-cert-file string
    	ECSDSA client cert used for authenticating to MQTT bus (default "dtm-mqtt-client.pem")
  -mqtt-client-id string
    	MQTT client id used for publishing events (default "dtm-pub")
  -mqtt-client-key-file string
    	ECSDSA client key used for authenticating to MQTT bus (default "dtm-mqtt-client-key.pem")
  -mqtt-keepalive int
    	Keepalive interval fo MQTT connection (default 30)
  -mqtt-server string
    	MQTT server we will publish events to (default "127.0.0.1:8883")
  -mqtt-signing-key-file string
    	ECSDSA key used for signing MQTT messages (default "dtm-mqtt-signer-key.pem")
  -mqtt-topic string
    	MQTT topic to publish events to (default "events/up/dtm/new_qname")
  -well-known-domains string
    	the dawg file used for filtering well-known domains (default "well-known-domains.dawg")
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
dtm -input-unix /opt/unbound/dnstap.sock
```

## Development
### Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:
* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
