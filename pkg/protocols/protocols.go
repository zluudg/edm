package protocols

import (
	"time"

	"github.com/miekg/dns"
)

// This file contains custom functions/methods around the content of generated.go

func NewQnameEvent(msg *dns.Msg, ts time.Time) EventsMqttMessageNewQnameJson {
	qType := int(msg.Question[0].Qtype)
	qClass := int(msg.Question[0].Qclass)
	return EventsMqttMessageNewQnameJson{
		Type:      "new_qname",
		Qname:     DomainName(msg.Question[0].Name),
		Qtype:     &qType,
		Qclass:    &qClass,
		Timestamp: ts,
	}
}
