package protocols

import (
	"time"

	"github.com/miekg/dns"
)

// This file contains custom functions/methods around the content of generated.go

// Consts and content of bitsFromMsg() borrowed from miekg/dns, see
// https://github.com/miekg/dns/issues/1499
const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
	_Z  = 1 << 6  // Z
	_AD = 1 << 5  // authenticated data
	_CD = 1 << 4  // checking disabled
)

func bitsFromMsg(dns *dns.Msg) uint16 {
	bits := uint16(dns.Opcode)<<11 | uint16(dns.Rcode&0xF)
	if dns.Response {
		bits |= _QR
	}
	if dns.Authoritative {
		bits |= _AA
	}
	if dns.Truncated {
		bits |= _TC
	}
	if dns.RecursionDesired {
		bits |= _RD
	}
	if dns.RecursionAvailable {
		bits |= _RA
	}
	if dns.Zero {
		bits |= _Z
	}
	if dns.AuthenticatedData {
		bits |= _AD
	}
	if dns.CheckingDisabled {
		bits |= _CD
	}

	return bits
}

func NewQnameEvent(msg *dns.Msg, ts time.Time) EventsMqttMessageNewQnameJson {
	bits := bitsFromMsg(msg)
	flags := int(bits)

	qType := int(msg.Question[0].Qtype)
	qClass := int(msg.Question[0].Qclass)

	return EventsMqttMessageNewQnameJson{
		Type:      "new_qname",
		Qname:     DomainName(msg.Question[0].Name),
		Qtype:     &qType,
		Qclass:    &qClass,
		Timestamp: ts,
		Flags:     &flags,
	}
}
