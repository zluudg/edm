package runner

import (
	"encoding/binary"
	"flag"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/smhanov/dawg"
)

var testDawg = flag.Bool("test-dawg", false, "perform tests requiring a well-known-domains.dawg file")

func BenchmarkWKDTIsKnown(b *testing.B) {
	if !*testDawg {
		b.Skip("skipping benchmark needing well-known-domains.dawg")
	}

	dawgFile := "well-known-domains.dawg"

	_, err := os.Stat(dawgFile)
	if err != nil {
		b.Fatal(err)
	}

	dawgFinder, err := dawg.Load(dawgFile)
	if err != nil {
		b.Error(err)
	}

	err = setHllDefaults()
	if err != nil {
		b.Fatalf("unable to set Hll defaults: %s", err)
	}

	wkdTracker, err := newWellKnownDomainsTracker(dawgFinder)
	if err != nil {
		b.Fatal(err)
	}

	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	ip, err := netip.ParseAddr("127.0.0.1")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		wkdTracker.isKnown(ip.AsSlice(), m)
	}
}

func BenchmarkSetHistogramLabels(b *testing.B) {
	b.ReportAllocs()
	labels := []string{"label0", "label1", "label2", "label3", "label4", "label5", "label6", "label7", "label8", "label9"}
	dtm := &dnstapMinimiser{}
	hd := &histogramData{}

	for i := 0; i < b.N; i++ {
		dtm.setHistogramLabels(labels, 10, hd)
	}
}

func TestWKD(t *testing.T) {

	domainList := []string{
		"example.com.",  // exact match
		".example.net.", // suffix match
	}

	// Make it so dawg Add() does not panic if the containts of domainList
	// is not in alphabetical order
	slices.Sort(domainList)

	dBuilder := dawg.New()

	for _, domain := range domainList {
		dBuilder.Add(domain)
	}

	dFinder := dBuilder.Finish()

	var wkdDawgIndexTests = []struct {
		name        string
		domain      string
		found       bool
		suffixMatch bool
	}{
		{
			name:        "found exact match",
			domain:      "example.com.",
			found:       true,
			suffixMatch: false,
		},
		{
			name:        "missing exact match",
			domain:      "www.example.com.",
			found:       false,
			suffixMatch: false,
		},
		{
			name:        "found suffix match",
			domain:      "www.example.net.",
			found:       true,
			suffixMatch: true,
		},
		{
			name:        "no match for for suffix entry",
			domain:      "example.net.",
			found:       false,
			suffixMatch: false,
		},
	}

	wkd, err := newWellKnownDomainsTracker(dFinder)
	if err != nil {
		t.Fatalf("unable to create well-known domains tracker: %s", err)
	}

	for _, test := range wkdDawgIndexTests {
		m := new(dns.Msg)
		m.SetQuestion(test.domain, dns.TypeA)
		i, suffixMatch := wkd.dawgIndex(m)

		if test.found && i == dawgNotFound {
			t.Fatalf("%s: expected match %s, but was not found", test.name, test.domain)
		}

		if !test.found && i != dawgNotFound {
			t.Fatalf("%s: expected not match for %s, but it was found", test.name, test.domain)
		}

		if suffixMatch != test.suffixMatch {
			t.Fatalf("%s: suffix match mismatch for %s, expected: %t, have: %t", test.name, test.domain, test.suffixMatch, suffixMatch)
		}
	}

	// Prepare for inserting Hll data when calling isKnown()
	err = setHllDefaults()
	if err != nil {
		t.Fatalf("unable to set HLL defaults: %s", err)
	}

	queryAddr4 := netip.MustParseAddr("198.51.100.20")
	queryAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:bbcc")

	var wkdIsKnownTests = []struct {
		name    string
		domain  string
		known   bool
		address []byte
	}{
		{
			name:    "known IPv4",
			domain:  "example.com.",
			known:   true,
			address: queryAddr4.AsSlice(),
		},
		{
			name:    "not known IPv4",
			domain:  "www.example.com.",
			known:   false,
			address: queryAddr4.AsSlice(),
		},
		{
			name:    "known IPv6",
			domain:  "example.com.",
			known:   true,
			address: queryAddr6.AsSlice(),
		},
		{
			name:    "not known IPv6",
			domain:  "www.example.com.",
			known:   false,
			address: queryAddr6.AsSlice(),
		},
	}

	for _, test := range wkdIsKnownTests {
		m := new(dns.Msg)
		m.SetQuestion(test.domain, dns.TypeA)

		known := wkd.isKnown(test.address, m)

		if test.known != known {
			t.Fatalf("%s: unexpected known status, have: %t, want: %t", test.name, known, test.known)
		}
	}

}

func TestSetHistogramLabels(t *testing.T) {
	// The reason the labels are "backwards" is because we define "label0"
	// in the struct as the rightmost DNS label, e.g. "com", "net" etc.
	name := "label9.label8.label7.label6.label5.label4.label3.label2.label1.label0."
	labels := dns.SplitDomainName(name)

	// Reverse labels to get easier comparision matching (offset 0 -> label0)
	compLabels := slices.Clone(labels)
	slices.Reverse(compLabels)

	dtm := &dnstapMinimiser{}
	hd := &histogramData{}

	dtm.setHistogramLabels(labels, 10, hd)

	if *hd.Label0 != compLabels[0] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, compLabels[0])
	}
	if *hd.Label1 != compLabels[1] {
		t.Fatalf("have: %s, want: %s", *hd.Label1, compLabels[1])
	}
	if *hd.Label2 != compLabels[2] {
		t.Fatalf("have: %s, want: %s", *hd.Label2, compLabels[2])
	}
	if *hd.Label3 != compLabels[3] {
		t.Fatalf("have: %s, want: %s", *hd.Label3, compLabels[3])
	}
	if *hd.Label4 != compLabels[4] {
		t.Fatalf("have: %s, want: %s", *hd.Label4, compLabels[4])
	}
	if *hd.Label5 != compLabels[5] {
		t.Fatalf("have: %s, want: %s", *hd.Label5, compLabels[5])
	}
	if *hd.Label6 != compLabels[6] {
		t.Fatalf("have: %s, want: %s", *hd.Label6, compLabels[6])
	}
	if *hd.Label7 != compLabels[7] {
		t.Fatalf("have: %s, want: %s", *hd.Label7, compLabels[7])
	}
	if *hd.Label8 != compLabels[8] {
		t.Fatalf("have: %s, want: %s", *hd.Label8, compLabels[8])
	}
	if *hd.Label9 != compLabels[9] {
		t.Fatalf("have: %s, want: %s", *hd.Label9, compLabels[9])
	}
}

func TestSetHistogramLabelsOverLimit(t *testing.T) {
	// The reason the labels are "backwards" is because we define "label0"
	// in the struct as the rightmost DNS label, e.g. "com", "net" etc.
	name := "label12.label11.label10.label9.label8.label7.label6.label5.label4.label3.label2.label1.label0."
	labels := dns.SplitDomainName(name)

	// Reverse labels to get easier comparision matching (offset 0 -> label0)
	compLabels := slices.Clone(labels)
	slices.Reverse(compLabels)

	dtm := &dnstapMinimiser{}
	hd := &histogramData{}

	// The label9 field contains all overflowing labels
	overflowLabels := slices.Clone(labels[:4])
	slices.Reverse(overflowLabels)
	combinedLastLabel := strings.Join(overflowLabels, ".")

	dtm.setHistogramLabels(labels, 10, hd)

	if *hd.Label0 != compLabels[0] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, compLabels[0])
	}
	if *hd.Label1 != compLabels[1] {
		t.Fatalf("have: %s, want: %s", *hd.Label1, compLabels[1])
	}
	if *hd.Label2 != compLabels[2] {
		t.Fatalf("have: %s, want: %s", *hd.Label2, compLabels[2])
	}
	if *hd.Label3 != compLabels[3] {
		t.Fatalf("have: %s, want: %s", *hd.Label3, compLabels[3])
	}
	if *hd.Label4 != compLabels[4] {
		t.Fatalf("have: %s, want: %s", *hd.Label4, compLabels[4])
	}
	if *hd.Label5 != compLabels[5] {
		t.Fatalf("have: %s, want: %s", *hd.Label5, compLabels[5])
	}
	if *hd.Label6 != compLabels[6] {
		t.Fatalf("have: %s, want: %s", *hd.Label6, compLabels[6])
	}
	if *hd.Label7 != compLabels[7] {
		t.Fatalf("have: %s, want: %s", *hd.Label7, compLabels[7])
	}
	if *hd.Label8 != compLabels[8] {
		t.Fatalf("have: %s, want: %s", *hd.Label8, compLabels[8])
	}
	if *hd.Label9 != combinedLastLabel {
		t.Fatalf("have: %s, want: %s", *hd.Label9, combinedLastLabel)
	}
}

func TestSetSessionLabels(t *testing.T) {
	// The reason the labels are "backwards" is because we define "label0"
	// in the struct as the rightmost DNS label, e.g. "com", "net" etc.
	labels := []string{"label9", "label8", "label7", "label6", "label5", "label4", "label3", "label2", "label1", "label0"}
	dtm := &dnstapMinimiser{}
	sd := &sessionData{}

	dtm.setSessionLabels(labels, 10, sd)

	if *sd.Label0 != labels[9] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[9])
	}
	if *sd.Label1 != labels[8] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[8])
	}
	if *sd.Label2 != labels[7] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[7])
	}
	if *sd.Label3 != labels[6] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[6])
	}
	if *sd.Label4 != labels[5] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[5])
	}
	if *sd.Label5 != labels[4] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[4])
	}
	if *sd.Label6 != labels[3] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[3])
	}
	if *sd.Label7 != labels[2] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[2])
	}
	if *sd.Label8 != labels[1] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[1])
	}
	if *sd.Label9 != labels[0] {
		t.Fatalf("have: %s, want: %s", *sd.Label0, labels[0])
	}
}

func TestDTMStatusBitsMulti(t *testing.T) {

	expectedString := "well-known-exact|well-known-wildcard"

	dsb := new(dtmStatusBits)
	dsb.set(dtmStatusWellKnownWildcard)
	dsb.set(dtmStatusWellKnownExact)

	if dsb.String() != expectedString {
		t.Fatalf("have: %s, want: %s", dsb.String(), expectedString)
	}
}

func TestDTMStatusBitsSingle(t *testing.T) {

	expectedString := "well-known-exact"

	dsb := new(dtmStatusBits)
	dsb.set(dtmStatusWellKnownExact)

	if dsb.String() != expectedString {
		t.Fatalf("have: %s, want: %s", dsb.String(), expectedString)
	}
}

func TestDTMStatusBitsMax(t *testing.T) {

	expectedString := "unknown flags in status"

	dsb := new(dtmStatusBits)
	dsb.set(dtmStatusMax)

	if !strings.HasPrefix(dsb.String(), "unknown flags in status: ") {
		t.Fatalf("have: %s, want prefix: %s", dsb.String(), expectedString)
	}
}

func TestDTMStatusBitsUnknown(t *testing.T) {

	expectedString := "unknown flags in status"

	dsb := new(dtmStatusBits)
	dsb.set(dtmStatusMax << 1)

	if !strings.HasPrefix(dsb.String(), "unknown flags in status: ") {
		t.Fatalf("have: %s, want prefix: %s", dsb.String(), expectedString)
	}
}

func TestDTMIPBytesToInt(t *testing.T) {

	ipv4AddrString := "198.51.100.15"

	ip4Addr, err := netip.ParseAddr(ipv4AddrString)
	if err != nil {
		t.Fatalf("unable to parse IPv4 test address '%s': %s", ipv4AddrString, err)
	}

	ip4Int, err := ipBytesToInt(ip4Addr.AsSlice())
	if err != nil {
		t.Fatalf("unable to create uint32 variable from IPv4 test address '%s': %s", ipv4AddrString, err)
	}

	// Go back to IPv4 data
	constructedV4Data := []byte{}
	constructedV4Data = binary.BigEndian.AppendUint32(constructedV4Data, ip4Int)

	constructedIp4Addr, ok := netip.AddrFromSlice(constructedV4Data)
	if !ok {
		t.Fatalf("unable to create netip from from constructed IPv4 bytes: %b", constructedV4Data)
	}

	if ip4Addr != constructedIp4Addr {
		t.Fatalf("have: %s, want: %s", constructedIp4Addr, ip4Addr)
	}
}

func TestDTMIP6BytesToInt(t *testing.T) {

	ipv6AddrString := "2001:db8:1122:3344:5566:7788:99aa:bbcc"

	ip6Addr, err := netip.ParseAddr(ipv6AddrString)
	if err != nil {
		t.Fatalf("unable to parse IPv6 test address '%s': %s", ipv6AddrString, err)
	}

	ip6Network, ip6Host, err := ip6BytesToInt(ip6Addr.AsSlice())
	if err != nil {
		t.Fatalf("unable to create uint64 variables from IPv6 test address '%s': %s", ipv6AddrString, err)
	}

	// Go back to complete IPv6 data
	constructedV6Data := []byte{}
	constructedV6Data = binary.BigEndian.AppendUint64(constructedV6Data, ip6Network)
	constructedV6Data = binary.BigEndian.AppendUint64(constructedV6Data, ip6Host)

	constructedIp6Addr, ok := netip.AddrFromSlice(constructedV6Data)
	if !ok {
		t.Fatalf("unable to create netip from from constructed IPv6 bytes: %b", constructedV6Data)
	}

	if ip6Addr != constructedIp6Addr {
		t.Fatalf("have: %s, want: %s", constructedIp6Addr, ip6Addr)
	}
}

func TestPseudonymiseDnstap(t *testing.T) {
	// Dont output logging
	// https://github.com/golang/go/issues/62005
	discardLogger := slog.NewTextHandler(io.Discard, nil)
	logger := slog.New(discardLogger)

	cryptopanSalt := "aabbccddeeffgghh"

	// The original addresses we want to pseudonymise
	origQueryAddr4 := netip.MustParseAddr("198.51.100.20")
	origRespAddr4 := netip.MustParseAddr("198.51.100.30")
	origQueryAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:bbcc")
	origRespAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:ddee")

	// The expected result given our first and second keys
	expectedPseudoQueryAddr4 := netip.MustParseAddr("58.92.11.53")
	expectedPseudoRespAddr4 := netip.MustParseAddr("58.92.11.62")
	expectedPseudoQueryAddrUpdated4 := netip.MustParseAddr("185.204.164.235")
	expectedPseudoRespAddrUpdated4 := netip.MustParseAddr("185.204.164.225")

	expectedPseudoQueryAddr6 := netip.MustParseAddr("b780:8dc8:6ed9:cbc5:4d61:a6bb:6255:5a03")
	expectedPseudoRespAddr6 := netip.MustParseAddr("b780:8dc8:6ed9:cbc5:4d61:a6bb:6255:262d")
	expectedPseudoQueryAddrUpdated6 := netip.MustParseAddr("3f29:478:21d2:2c44:6915:7ca7:8654:aa28")
	expectedPseudoRespAddrUpdated6 := netip.MustParseAddr("3f29:478:21d2:2c44:6915:7ca7:8654:d21f")

	dt4 := &dnstap.Dnstap{
		Message: &dnstap.Message{
			QueryAddress:    origQueryAddr4.AsSlice(),
			ResponseAddress: origRespAddr4.AsSlice(),
		},
	}
	dt6 := &dnstap.Dnstap{
		Message: &dnstap.Message{
			QueryAddress:    origQueryAddr6.AsSlice(),
			ResponseAddress: origRespAddr6.AsSlice(),
		},
	}

	cryptopanCacheSize := 10

	dtm, err := newDnstapMinimiser(logger, "key1", cryptopanSalt, cryptopanCacheSize, false)
	if err != nil {
		t.Fatalf("unable to setup dtm: %s", err)
	}

	if dtm.cryptopanCache != nil {
		if dtm.cryptopanCache.Len() != 0 {
			t.Fatalf("there should be no entries in newly initialised cryptopan cache but it contains items: %d", dtm.cryptopanCache.Len())
		}
	}

	dtm.pseudonymiseDnstap(dt4)
	dtm.pseudonymiseDnstap(dt6)

	pseudoQueryAddr4, ok := netip.AddrFromSlice(dt4.Message.QueryAddress)
	if !ok {
		t.Fatal("unable to parse IPv4 QueryAddress")
	}
	pseudoRespAddr4, ok := netip.AddrFromSlice(dt4.Message.ResponseAddress)
	if !ok {
		t.Fatal("unable to parse IPv4 ResponseAddress")
	}

	pseudoQueryAddr6, ok := netip.AddrFromSlice(dt6.Message.QueryAddress)
	if !ok {
		t.Fatal("unable to parse IPv6 QueryAddress")
	}
	pseudoRespAddr6, ok := netip.AddrFromSlice(dt6.Message.ResponseAddress)
	if !ok {
		t.Fatal("unable to parse IPv6 ResponseAddress")
	}

	// Verify we are not accidentally getting IPv4-mapped IPv6 address
	if !pseudoQueryAddr4.Is4() {
		t.Fatalf("pseudonymised IPv4 query address appears to be IPv4-mapped IPv6 address: %s", pseudoQueryAddr4)
	}
	if !pseudoRespAddr4.Is4() {
		t.Fatalf("pseudonymised IPv4 response address appears to be IPv4-mapped IPv6 address: %s", pseudoRespAddr4)
	}

	// Verify they are different from the original addresses
	if origQueryAddr4 == pseudoQueryAddr4 {
		t.Fatalf("pseudonymised IPv4 query address %s is the same as the orignal address %s", pseudoQueryAddr4, origQueryAddr4)
	}
	if origRespAddr4 == pseudoRespAddr4 {
		t.Fatalf("pseudonymised IPv4 response address %s is the same as the orignal address %s", pseudoRespAddr4, origRespAddr4)
	}
	if origQueryAddr6 == pseudoQueryAddr6 {
		t.Fatalf("pseudonymised IPv6 query address %s is the same as the orignal address %s", pseudoQueryAddr6, origQueryAddr6)
	}
	if origRespAddr6 == pseudoRespAddr6 {
		t.Fatalf("pseudonymised IPv6 response address %s is the same as the orignal address %s", pseudoRespAddr6, origRespAddr6)
	}

	// Verify they are different as expected
	if pseudoQueryAddr4 != expectedPseudoQueryAddr4 {
		t.Fatalf("pseudonymised IPv4 query address %s is not the expected address %s", pseudoQueryAddr4, expectedPseudoQueryAddr4)
	}
	if pseudoRespAddr4 != expectedPseudoRespAddr4 {
		t.Fatalf("pseudonymised IPv4 resp address %s is not the expected address %s", pseudoRespAddr4, expectedPseudoRespAddr4)
	}
	if pseudoQueryAddr6 != expectedPseudoQueryAddr6 {
		t.Fatalf("pseudonymised IPv6 query address %s is not the expected address %s", pseudoQueryAddr6, expectedPseudoQueryAddr6)
	}
	if pseudoRespAddr6 != expectedPseudoRespAddr6 {
		t.Fatalf("pseudonymised IPv6 resp address %s is not the expected address %s", pseudoRespAddr6, expectedPseudoRespAddr6)
	}

	if dtm.cryptopanCache != nil {
		if dtm.cryptopanCache.Len() == 0 {
			t.Fatalf("there should be entries in the cryptopan cache but it is empty")
		}

		// Verify the entry in the cache is the same as the one we got back
		cachedPseudoQueryAddr4, ok := dtm.cryptopanCache.Get(origQueryAddr4)
		if !ok {
			t.Fatalf("unable to lookup IPv4 query address %s in cache", origQueryAddr4)
		}
		if cachedPseudoQueryAddr4 != pseudoQueryAddr4 {
			t.Fatalf("cached pseudonymised IPv4 query address %s is not the same as the calculated address %s", cachedPseudoQueryAddr4, pseudoQueryAddr4)
		}

		cachedPseudoRespAddr4, ok := dtm.cryptopanCache.Get(origRespAddr4)
		if !ok {
			t.Fatalf("unable to lookup IPv4 response address %s in cache", origRespAddr4)
		}
		if cachedPseudoRespAddr4 != pseudoRespAddr4 {
			t.Fatalf("cached pseudonymised IPv4 response address %s is not the same as the calculated address %s", cachedPseudoRespAddr4, pseudoRespAddr4)
		}

		cachedPseudoQueryAddr6, ok := dtm.cryptopanCache.Get(origQueryAddr6)
		if !ok {
			t.Fatalf("unable to lookup IPv6 query address %s in cache", origQueryAddr6)
		}
		if cachedPseudoQueryAddr6 != pseudoQueryAddr6 {
			t.Fatalf("cached pseudonymised IPv6 query address %s is not the same as the calculated address %s", cachedPseudoQueryAddr6, pseudoQueryAddr6)
		}

		cachedPseudoRespAddr6, ok := dtm.cryptopanCache.Get(origRespAddr6)
		if !ok {
			t.Fatalf("unable to lookup IPv6 response address %s in cache", origRespAddr6)
		}
		if cachedPseudoRespAddr6 != pseudoRespAddr6 {
			t.Fatalf("cached pseudonymised IPv6 response address %s is not the same as the calculated address %s", cachedPseudoRespAddr6, pseudoRespAddr6)
		}
	}

	if dtm.cryptopanCache != nil {
		t.Logf("number of pseudonymisation cache entries before reset: %d", dtm.cryptopanCache.Len())
	}

	if dtm.cryptopanCache != nil {
		for _, key := range dtm.cryptopanCache.Keys() {
			value, ok := dtm.cryptopanCache.Get(key)
			if !ok {
				t.Fatalf("unable to extract value for key before reset: %s", key)
			}

			t.Logf("inital cache key: %s, value: %s", key, value)
		}
	}

	// Replace the cryptopan instance and verify we now get different pseudonymised results
	err = dtm.setCryptopan("key2", cryptopanSalt, cryptopanCacheSize)
	if err != nil {
		t.Fatalf("unable to call dtm.SetCryptopan: %s", err)
	}

	if dtm.cryptopanCache != nil {
		if dtm.cryptopanCache.Len() != 0 {
			t.Fatalf("there should be no cache entries in replaced cryptopan cache but it contains items: %d", dtm.cryptopanCache.Len())
		}
	}

	// Reset the addresses and pseudonymise again with the updated key
	dt4.Message.QueryAddress = origQueryAddr4.AsSlice()
	dt4.Message.ResponseAddress = origRespAddr4.AsSlice()
	dt6.Message.QueryAddress = origQueryAddr6.AsSlice()
	dt6.Message.ResponseAddress = origRespAddr6.AsSlice()

	dtm.pseudonymiseDnstap(dt4)
	dtm.pseudonymiseDnstap(dt6)

	pseudoQueryAddrUpdated4, ok := netip.AddrFromSlice(dt4.Message.QueryAddress)
	if !ok {
		t.Fatal("unable to parse second IPv4 QueryAddress")
	}
	pseudoRespAddrUpdated4, ok := netip.AddrFromSlice(dt4.Message.ResponseAddress)
	if !ok {
		t.Fatal("unable to parse second IPv4 ResponseAddress")
	}
	pseudoQueryAddrUpdated6, ok := netip.AddrFromSlice(dt6.Message.QueryAddress)
	if !ok {
		t.Fatal("unable to parse second IPv6 QueryAddress")
	}
	pseudoRespAddrUpdated6, ok := netip.AddrFromSlice(dt6.Message.ResponseAddress)
	if !ok {
		t.Fatal("unable to parse second IPv6 ResponseAddress")
	}

	// Verify they are different from the original addresses
	if origQueryAddr4 == pseudoQueryAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv4 query address %s is the same as the orignal address %s", pseudoQueryAddrUpdated4, origQueryAddr4)
	}
	if origRespAddr4 == pseudoRespAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv4 response address %s is the same as the orignal address %s", pseudoRespAddrUpdated4, origRespAddr4)
	}
	if origQueryAddr6 == pseudoQueryAddrUpdated6 {
		t.Fatalf("updated pseudonymised IPv6 query address %s is the same as the orignal address %s", pseudoQueryAddrUpdated6, origQueryAddr6)
	}
	if origRespAddr4 == pseudoRespAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv6 response address %s is the same as the orignal address %s", pseudoRespAddrUpdated6, origRespAddr6)
	}

	// Verify the new pseudo addresses are different from the previous pseudo addresses
	if pseudoQueryAddr4 == pseudoQueryAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv4 query address %s is the same as the orignal pseudonymised address %s", pseudoQueryAddrUpdated4, pseudoQueryAddr4)
	}
	if pseudoRespAddr4 == pseudoRespAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv4 response address %s is the same as the orignal pseudonymised address %s", pseudoRespAddrUpdated4, pseudoRespAddr4)
	}
	if pseudoQueryAddr6 == pseudoQueryAddrUpdated6 {
		t.Fatalf("updated pseudonymised IPv6 query address %s is the same as the orignal pseudonymised address %s", pseudoQueryAddrUpdated6, pseudoQueryAddr6)
	}
	if pseudoRespAddr6 == pseudoRespAddrUpdated6 {
		t.Fatalf("updated pseudonymised IPv6 response address %s is the same as the orignal pseudonymised address %s", pseudoRespAddrUpdated6, pseudoRespAddr6)
	}

	// Verify they are different as expected
	if pseudoQueryAddrUpdated4 != expectedPseudoQueryAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv4 query address %s is not the expected address %s", pseudoQueryAddrUpdated4, expectedPseudoQueryAddrUpdated4)
	}
	if pseudoRespAddrUpdated4 != expectedPseudoRespAddrUpdated4 {
		t.Fatalf("updated pseudonymised IPv4 resp address %s is not the expected address %s", pseudoRespAddrUpdated4, expectedPseudoRespAddrUpdated4)
	}
	if pseudoQueryAddrUpdated6 != expectedPseudoQueryAddrUpdated6 {
		t.Fatalf("updated pseudonymised IPv6 query address %s is not the expected address %s", pseudoQueryAddrUpdated6, expectedPseudoQueryAddrUpdated6)
	}
	if pseudoRespAddrUpdated6 != expectedPseudoRespAddrUpdated6 {
		t.Fatalf("updated pseudonymised IPv6 resp address %s is not the expected address %s", pseudoRespAddrUpdated6, expectedPseudoRespAddrUpdated6)
	}

	if dtm.cryptopanCache != nil {
		t.Logf("number of pseudonymisation cache entries before end: %d", dtm.cryptopanCache.Len())
		for _, key := range dtm.cryptopanCache.Keys() {
			value, ok := dtm.cryptopanCache.Get(key)
			if !ok {
				t.Fatalf("unable to extract value for key before end: %s", key)
			}

			t.Logf("reset cache key: %s, value: %s", key, value)
		}
	}
}

func BenchmarkPseudonymiseDnstapWithCache4(b *testing.B) {
	b.ReportAllocs()

	// Dont output logging
	// https://github.com/golang/go/issues/62005
	discardLogger := slog.NewTextHandler(io.Discard, nil)
	logger := slog.New(discardLogger)

	cryptopanSalt := "aabbccddeeffgghh"

	// The original addresses we want to pseudonymise
	origQueryAddr4 := netip.MustParseAddr("198.51.100.20")
	origRespAddr4 := netip.MustParseAddr("198.51.100.30")

	cryptopanCacheSize := 10

	dtm, err := newDnstapMinimiser(logger, "key1", cryptopanSalt, cryptopanCacheSize, false)
	if err != nil {
		b.Fatalf("unable to setup dtm: %s", err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dt4 := &dnstap.Dnstap{
			Message: &dnstap.Message{
				QueryAddress:    origQueryAddr4.AsSlice(),
				ResponseAddress: origRespAddr4.AsSlice(),
			},
		}
		dtm.pseudonymiseDnstap(dt4)
	}
}

func BenchmarkPseudonymiseDnstapWithoutCache4(b *testing.B) {
	b.ReportAllocs()

	// Dont output logging
	// https://github.com/golang/go/issues/62005
	discardLogger := slog.NewTextHandler(io.Discard, nil)
	logger := slog.New(discardLogger)

	cryptopanSalt := "aabbccddeeffgghh"

	// The original addresses we want to pseudonymise
	origQueryAddr4 := netip.MustParseAddr("198.51.100.20")
	origRespAddr4 := netip.MustParseAddr("198.51.100.30")

	cryptopanCacheSize := 0

	dtm, err := newDnstapMinimiser(logger, "key1", cryptopanSalt, cryptopanCacheSize, false)
	if err != nil {
		b.Fatalf("unable to setup dtm: %s", err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dt4 := &dnstap.Dnstap{
			Message: &dnstap.Message{
				QueryAddress:    origQueryAddr4.AsSlice(),
				ResponseAddress: origRespAddr4.AsSlice(),
			},
		}
		dtm.pseudonymiseDnstap(dt4)
	}
}

func BenchmarkPseudonymiseDnstapWithCache6(b *testing.B) {
	b.ReportAllocs()

	// Dont output logging
	// https://github.com/golang/go/issues/62005
	discardLogger := slog.NewTextHandler(io.Discard, nil)
	logger := slog.New(discardLogger)

	cryptopanSalt := "aabbccddeeffgghh"

	// The original addresses we want to pseudonymise
	origQueryAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:bbcc")
	origRespAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:ddee")

	cryptopanCacheSize := 10

	dtm, err := newDnstapMinimiser(logger, "key1", cryptopanSalt, cryptopanCacheSize, false)
	if err != nil {
		b.Fatalf("unable to setup dtm: %s", err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dt6 := &dnstap.Dnstap{
			Message: &dnstap.Message{
				QueryAddress:    origQueryAddr6.AsSlice(),
				ResponseAddress: origRespAddr6.AsSlice(),
			},
		}
		dtm.pseudonymiseDnstap(dt6)
	}
}

func BenchmarkPseudonymiseDnstapWithoutCache6(b *testing.B) {
	b.ReportAllocs()

	// Dont output logging
	// https://github.com/golang/go/issues/62005
	discardLogger := slog.NewTextHandler(io.Discard, nil)
	logger := slog.New(discardLogger)

	cryptopanSalt := "aabbccddeeffgghh"

	// The original addresses we want to pseudonymise
	origQueryAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:bbcc")
	origRespAddr6 := netip.MustParseAddr("2001:db8:1122:3344:5566:7788:99aa:ddee")

	cryptopanCacheSize := 0

	dtm, err := newDnstapMinimiser(logger, "key1", cryptopanSalt, cryptopanCacheSize, false)
	if err != nil {
		b.Fatalf("unable to setup dtm: %s", err)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dt6 := &dnstap.Dnstap{
			Message: &dnstap.Message{
				QueryAddress:    origQueryAddr6.AsSlice(),
				ResponseAddress: origRespAddr6.AsSlice(),
			},
		}
		dtm.pseudonymiseDnstap(dt6)
	}
}
