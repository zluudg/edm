protocols.go: protocols/events-mqtt-message-new_qname.json
	go-jsonschema checkout/events-mqtt-message-new_qname.json --package protocols --tags json --only-models --output generated.go
protocols/events-mqtt-message-new_qname.json: checkout
	cd checkout; python3 schemasplit.py events-mqtt-message.yaml
checkout:
	git clone git@github.com:dnstapir/protocols.git checkout
