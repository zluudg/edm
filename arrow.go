package main

import (
	"strconv"

	"github.com/apache/arrow/go/v13/arrow"
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

func dnsSessionRowArrowSchema() *arrow.Schema {
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

	return arrow.NewSchema(
		arrowFields,
		nil,
	)
}
