package main

import (
	"strconv"

	"github.com/apache/arrow/go/v14/arrow"
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
	arrowFields = append(arrowFields, arrow.Field{Name: "query_message", Type: arrow.BinaryTypes.Binary, Nullable: true})
	arrowFields = append(arrowFields, arrow.Field{Name: "response_message", Type: arrow.BinaryTypes.Binary, Nullable: true})

	return arrow.NewSchema(
		arrowFields,
		nil,
	)
}
