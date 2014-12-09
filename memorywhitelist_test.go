package main

import (
	"fmt"
	"net/url"
	"os"
	"testing"
)

func BenchmarkMemoryManagerMatching(b *testing.B) {
	fmt.Println()
	b.StopTimer()
	twm, err := NewMemoryWhitelistManager("tempmem.csv")
	if err != nil {
		b.Fatalf("Error starting memory whitelist manager - %t", err)
	}
	defer func() {
		twm.file.Close()
		os.RemoveAll("tempmem.csv")
	}()
	benchManager(twm, b)
	b.StopTimer()
}

func benchManager(wlm WhiteListManager, b *testing.B) {
	b.StartTimer()
	for _, p := range patterns {
		wlm.Add(p.e)
	}
	for i := 0; i < b.N; i++ {
		for j, s := range testingSites {
			u, _ := url.Parse(s.URL)
			result := wlm.Check(Site{URL: u})
			if result != s.Check {
				b.Errorf("[%d] For URL %s - expected %t, got %t", j, u, s.Check, result)
			}
		}
	}
}

func TestMemoryWhiteListManagerAdd(t *testing.T) {
	fmt.Println()
	twm, err := NewMemoryWhitelistManager("tempmem.csv")
	if err != nil {
		t.Fatalf("Error starting memory whitelist manager - %t", err)
	}
	defer func() {
		twm.file.Close()
		os.RemoveAll("tempmem.csv")
	}()
	twm.entries = twm.entries[:0]
	for i, p := range patterns {
		got := twm.add(p.e, false)
		if p.val != got {
			t.Errorf("Got %d, wanted %v, for entry #%d - %v", got, p.val, i, p.e)
		}
	}
}
