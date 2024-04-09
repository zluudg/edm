package runner

import (
	"encoding/binary"
	"flag"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/segmentio/go-hll"
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

	err = hll.Defaults(hll.Settings{
		Log2m:             10,
		Regwidth:          4,
		ExplicitThreshold: hll.AutoExplicitThreshold,
		SparseEnabled:     true,
	})
	if err != nil {
		b.Fatal(err)
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
		setHistogramLabels(dtm, labels, 10, hd)
	}
}

func TestSetHistogramLabels(t *testing.T) {
	// The reason the labels are "backwards" is because we define "label0"
	// in the struct as the rightmost DNS label, e.g. "com", "net" etc.
	labels := []string{"label9", "label8", "label7", "label6", "label5", "label4", "label3", "label2", "label1", "label0"}
	dtm := &dnstapMinimiser{}
	hd := &histogramData{}

	setHistogramLabels(dtm, labels, 10, hd)

	if *hd.Label0 != labels[9] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[9])
	}
	if *hd.Label1 != labels[8] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[8])
	}
	if *hd.Label2 != labels[7] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[7])
	}
	if *hd.Label3 != labels[6] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[6])
	}
	if *hd.Label4 != labels[5] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[5])
	}
	if *hd.Label5 != labels[4] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[4])
	}
	if *hd.Label6 != labels[3] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[3])
	}
	if *hd.Label7 != labels[2] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[2])
	}
	if *hd.Label8 != labels[1] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[1])
	}
	if *hd.Label9 != labels[0] {
		t.Fatalf("have: %s, want: %s", *hd.Label0, labels[0])
	}
}

func TestSetSessionLabels(t *testing.T) {
	// The reason the labels are "backwards" is because we define "label0"
	// in the struct as the rightmost DNS label, e.g. "com", "net" etc.
	labels := []string{"label9", "label8", "label7", "label6", "label5", "label4", "label3", "label2", "label1", "label0"}
	dtm := &dnstapMinimiser{}
	sd := &sessionData{}

	setSessionLabels(dtm, labels, 10, sd)

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
