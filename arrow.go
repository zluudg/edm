package main

import (
	"strconv"
	"strings"

	"github.com/apache/arrow/go/v14/arrow"
	"github.com/miekg/dns"
)

// Based on https://github.com/dnstapir/datasets/blob/main/dnstap2clickhouse.schema
func createLabelFields() []arrow.Field {
	arrowFields := []arrow.Field{}
	for i := 0; i < 10; i++ {
		arrowFields = append(
			arrowFields,
			arrow.Field{
				Name:     "label" + strconv.Itoa(i),
				Type:     arrow.BinaryTypes.String,
				Nullable: true,
			},
		)
	}

	return arrowFields
}

func dnsSessionRowArrowSchema() (*arrow.Schema, map[uint16]arrow.UnionTypeCode) {
	arrowFields := []arrow.Field{}

	// FQDN as key
	arrowFields = append(arrowFields, createLabelFields()...)

	// Timestamps
	arrowFields = append(arrowFields, arrow.Field{Name: "query_time", Type: arrow.FixedWidthTypes.Timestamp_ns, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "response_time", Type: arrow.FixedWidthTypes.Timestamp_ns, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "server_id", Type: arrow.BinaryTypes.Binary, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "source_ipv4", Type: arrow.PrimitiveTypes.Uint32, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "dest_ipv4", Type: arrow.PrimitiveTypes.Uint32, Nullable: true})
	// IPv6 addresses are split up into a network and host part, for one thing arrow (or go) does not have native uint128 types
	arrowFields = append(arrowFields, arrow.Field{Name: "source_ipv6_network", Type: arrow.PrimitiveTypes.Uint64, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "source_ipv6_host", Type: arrow.PrimitiveTypes.Uint64, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "dest_ipv6_network", Type: arrow.PrimitiveTypes.Uint64, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "dest_ipv6_host", Type: arrow.PrimitiveTypes.Uint64, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "source_port", Type: arrow.PrimitiveTypes.Uint16, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "dest_port", Type: arrow.PrimitiveTypes.Uint16, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "dns_protocol", Type: arrow.PrimitiveTypes.Uint8, Nullable: true})

	// Common struct fields between qheader/rheader
	headerFields := []arrow.Field{
		{Name: "id", Type: arrow.PrimitiveTypes.Uint16},
	}
	// Common struct fields between qcounteris/rcounters
	counterFields := []arrow.Field{
		{Name: "qd", Type: arrow.PrimitiveTypes.Uint16},
		{Name: "an", Type: arrow.PrimitiveTypes.Uint16},
		{Name: "ns", Type: arrow.PrimitiveTypes.Uint16},
		{Name: "ar", Type: arrow.PrimitiveTypes.Uint16},
	}
	arrowFields = append(arrowFields, arrow.Field{Name: "qheader", Type: arrow.StructOf(headerFields...), Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "qcounters", Type: arrow.StructOf(counterFields...), Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "rheader", Type: arrow.StructOf(headerFields...), Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "rcounters", Type: arrow.StructOf(counterFields...), Nullable: true})

	rdAFields := []arrow.Field{
		{Name: "address", Type: arrow.PrimitiveTypes.Uint32},
	}

	rdataFields := []arrow.Field{
		{Name: "Rd_A", Type: arrow.StructOf(rdAFields...)},
	}

	rdataFieldTypeCodes := []arrow.UnionTypeCode{}
	rDataFieldUnionTypeMap := map[uint16]arrow.UnionTypeCode{}
	for i, rdataField := range rdataFields {
		rdataFieldTypeCodes = append(rdataFieldTypeCodes, int8(i))
		// We need a way to fetch what type code relates to a given record type in the main code, so create a map between record type uint16 to union type code number
		nameParts := strings.Split(rdataField.Name, "_")
		// Find the uint16 for a type e.g. A, AAAA
		recordTypeInt := dns.StringToType[nameParts[1]]

		// We now map the record type uint16 to the "code type" (index) of our union, e.g. 1 (A) -> 0, 28 (AAAA) -> 1
		rDataFieldUnionTypeMap[recordTypeInt] = int8(i)
	}
	recordFields := []arrow.Field{
		{Name: "name", Type: arrow.BinaryTypes.String},
		{Name: "type", Type: arrow.PrimitiveTypes.Uint16},
		{Name: "class", Type: arrow.PrimitiveTypes.Uint16},
		{Name: "ttl", Type: arrow.PrimitiveTypes.Uint32},
		{Name: "rdlength", Type: arrow.PrimitiveTypes.Uint16},
		{Name: "rdata", Type: arrow.DenseUnionOf(rdataFields, rdataFieldTypeCodes)},
	}
	arrowFields = append(arrowFields, arrow.Field{Name: "records", Type: arrow.ListOf(arrow.StructOf(recordFields...)), Nullable: true})

	return arrow.NewSchema(
		arrowFields,
		nil,
	), rDataFieldUnionTypeMap
}
