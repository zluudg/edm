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

func dnsSessionRowFields() []arrow.Field {
	arrowFields := []arrow.Field{}

	// FQDN as key
	arrowFields = append(arrowFields, createLabelFields()...)

	return arrowFields
}

func dnsSessionBlockArrowSchema() *arrow.Schema {

	arrowFields := []arrow.Field{}

	arrowFields = append(arrowFields, arrow.Field{Name: "start_time", Type: arrow.FixedWidthTypes.Timestamp_ns})
	arrowFields = append(arrowFields, arrow.Field{Name: "stop_time", Type: arrow.FixedWidthTypes.Timestamp_ns})
	arrowFields = append(arrowFields, arrow.Field{Name: "sessions", Type: arrow.ListOf(arrow.StructOf(dnsSessionRowFields()...))})

	arrowSchema := arrow.NewSchema(
		arrowFields,
		nil,
	)

	return arrowSchema
}
