package main

import (
	"os"
	"testing"

	"github.com/miekg/dns"
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

	wkdTracker := &wellKnownDomainsTracker{
		wellKnownDomainsData: wellKnownDomainsData{
			m:          map[int]*histogramData{},
			dawgFinder: dawgFinder,
		},
	}

	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		wkdTracker.isKnown(m.Question[0])
	}
}
