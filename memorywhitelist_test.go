package main

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
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
	patterns := []struct {
		val int
		e   Entry
	}{
		{1, NewEntry("www.google.com", false, "", "", 0)},
		{-1, NewEntry("www.google.com", true, "", "", 0)},
		{1, NewEntry("other.google.com", true, "", "", 0)},
		{-2, NewEntry("google.com", true, "", "", 0)},
		{0, NewEntry("explicit.google.com", false, "", "", 0)},
		{0, NewEntry("wildcard.google.com", true, "", "", 0)},
		{1, NewEntry("path.com", false, "/path", "", 0)},
		{0, NewEntry("path.com", false, "/path/too", "", 0)},
		{1, NewEntry("travis-ci.org", false, "", "", 0)},
		{1, NewEntry("com", true, "", "", 0)},       // this in invalid input, use NewEntry to "clean" it and make it a non-wildcard entry
		{0, NewEntry("com", false, "", "", 0)},      // test that this is not added as it is a duplicate
		{0, NewEntry("com", false, "/path", "", 0)}, // test that this is not added as it is superceded by path
	}
	for _, p := range patterns {
		wlm.Add(p.e)
	}
	testingSites := []struct {
		URL     string
		Check   bool
		Referer string
	}{
		{"http://www.google.com", true, "http://referer"},
		{"https://www.google.com", true, "http://referer"},
		{"http://child.www.google.com", true, "http://referer"},
		{"https://child.www.google.com", true, "http://referer"},
		{"http://google.com", true, "http://referer"},
		{"http://google.com?query=true", true, "http://referer"},
		{"http://google.com/?query=true", true, "http://referer"},
		{"http://www.google.company", false, "http://referer"},
		{"https://www.google.company", false, "http://referer"},
		{"http://child.www.google.company", false, "http://referer"},
		{"https://child.www.google.company", false, "http://referer"},
		{"http://google.company", false, "http://referer"},
		{"http://google.company?query=true", false, "http://referer"},
		{"http://google.company/?query=true", false, "http://referer"},
		{"http://path.com/path?query=true", true, "http://referer"},
		{"http://path.com/path/?query=true", true, "http://referer"},
		{"http://www.path.com/path?query=true", false, "http://referer"},
		{"http://www.path.com/path/?query=true", false, "http://referer"},
		{"http://path.com/path/good?query=true", true, "http://referer"},
		{"https://path.com/path/good?query=true", true, "http://referer"},
		{"http://path.com/path/good/?query=true", true, "http://referer"},
		{"http://path.com/falsepath?query=true", false, "http://referer"},
		{"http://path.com/falsepath/?query=true", false, "http://referer"},
		{"http://path.com/falsepath/", false, "http://referer"},
		{"http://path.com/falsepath", false, "http://referer"},
		{"http://path.com/pathfalse?query=true", false, "http://referer"},
		{"http://path.com/pathfalse/?query=true", false, "http://referer"},
		{"http://path.com/pathfalse/", false, "http://referer"},
		{"http://path.com/pathfalse", false, "http://referer"},
		{"http://path.com/", false, "http://referer"},
		{"http://path.com", false, "http://referer"},
		{"http://travis-ci.org", true, "http://referer"},
		{"https://travis-ci.org", true, "http://referer"},
		{"http://www.travis-ci.org", false, "http://referer"},
		{"http://www.mdlottery.com", false, "http://referer"},
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

func TestMemoryWhiteListManagerExpire(t *testing.T) {
	fmt.Println()
	twm, err := NewMemoryWhitelistManager("tempmem.json")
	if err != nil {
		t.Fatalf("Error starting memory whitelist manager - %t", err)
	}
	defer func() {
		twm.file.Close()
		os.RemoveAll("tempmem.json")
	}()
	patterns := []struct {
		val int
		e   Entry
	}{
		{1, NewEntry("www.google.com", false, "", "", -10*time.Second)}, // 1
		{-1, NewEntry("www.google.com", true, "", "", -5*time.Second)},  // 2, will be added and remove the first, 2
		{1, NewEntry("www.google.com", false, "", "", 0)},               // 3, will be added but no removal, 2, 3
		{-1, NewEntry("www.google.com", true, "", "", 5*time.Second)},   //4, will be added and remove the 2nd, 3, 4
		{-1, NewEntry("google.com", true, "", "", 10*time.Second)},      // 5, will be added and remove the 4th, 3, 5
		{-1, NewEntry("www.google.com", true, "", "", 0)},               // 6, will be added and remove the 3rd, 5, 6
	}
	for i, p := range patterns {
		got := twm.add(p.e, false)
		if p.val != got {
			t.Errorf("Got %d, wanted %v, for entry #%d - %v", got, p.val, i, p.e)
		}
	}
}

func TestMemoryWhiteListManagerAdd(t *testing.T) {
	fmt.Println()
	twm, err := NewMemoryWhitelistManager("tempmem.json")
	if err != nil {
		t.Fatalf("Error starting memory whitelist manager - %t", err)
	}
	defer func() {
		twm.file.Close()
		os.RemoveAll("tempmem.csv")
	}()
	twm.entries = twm.entries[:0]
	patterns := []struct {
		val int
		e   Entry
	}{
		{1, NewEntry("www.google.com", false, "", "", 0)},
		{-1, NewEntry("www.google.com", true, "", "", 0)},
		{1, NewEntry("other.google.com", true, "", "", 0)},
		{-2, NewEntry("google.com", true, "", "", 0)},
		{0, NewEntry("explicit.google.com", false, "", "", 0)},
		{0, NewEntry("wildcard.google.com", true, "", "", 0)},
		{1, NewEntry("path.com", false, "/path", "", 0)},
		{0, NewEntry("path.com", false, "/path/too", "", 0)},
		{1, NewEntry("travis-ci.org", false, "", "", 0)},
		{1, NewEntry("com", true, "", "", 0)},       // this in invalid input, use NewEntry to "clean" it and make it a non-wildcard entry
		{0, NewEntry("com", false, "", "", 0)},      // test that this is not added as it is a duplicate
		{0, NewEntry("com", false, "/path", "", 0)}, // test that this is not added as it is superceded by path
	}
	for i, p := range patterns {
		got := twm.add(p.e, false)
		if p.val != got {
			t.Errorf("Got %d, wanted %v, for entry #%d - %v", got, p.val, i, p.e)
		}
	}
}
