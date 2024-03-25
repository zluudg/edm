package runner

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/segmentio/go-hll"
	"github.com/smhanov/dawg"
)

func BenchmarkWKDTIsKnown(b *testing.B) {
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
