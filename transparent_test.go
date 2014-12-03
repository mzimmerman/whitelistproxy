package main

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"testing"
)

func TestPaths(t *testing.T) {
	testPaths := []struct {
		source   string
		expected []string
	}{
		{"/", []string{}},
		{"blah", []string{}},
		{"/go", []string{"/go"}},
		{"/go/be", []string{"/go/be", "/go"}},
		{"/go/be/gopher", []string{"/go/be/gopher", "/go/be", "/go"}},
	}
	for _, tp := range testPaths {
		result := paths(tp.source)
		if !reflect.DeepEqual(result, tp.expected) {
			t.Errorf("on %s, got %v, expected %v", tp.source, result, tp.expected)
		}
	}
}

func TestRoots(t *testing.T) {
	testRoots := []struct {
		source   string
		expected []string
	}{
		{"org", []string{}},
		{"golang.org", []string{"golang.org"}},
		{"me.golang.org", []string{"me.golang.org", "golang.org"}},
		{"you.me.golang.org", []string{"you.me.golang.org", "me.golang.org", "golang.org"}},
		{"all.you.me.golang.org", []string{"all.you.me.golang.org", "you.me.golang.org", "me.golang.org", "golang.org"}},
	}
	for _, tr := range testRoots {
		result := rootDomains(tr.source)
		if !reflect.DeepEqual(result, tr.expected) {
			t.Errorf("on %s, got %v, expected %v", tr.source, result, tr.expected)
		}
	}
}

var patterns = []struct {
	val int
	e   Entry
}{
	{1, NewEntry("www.google.com", false, "", "")},
	{-1, NewEntry("www.google.com", true, "", "")},
	{1, NewEntry("other.google.com", true, "", "")},
	{-2, NewEntry("google.com", true, "", "")},
	{0, NewEntry("explicit.google.com", false, "", "")},
	{0, NewEntry("wildcard.google.com", true, "", "")},
	{1, NewEntry("path.com", false, "/path", "")},
	{0, NewEntry("path.com", false, "/path/too", "")},
	{1, NewEntry("travis-ci.org", false, "", "")},
	{1, NewEntry("com", true, "", "")},       // this in invalid input, use NewEntry to "clean" it and make it a non-wildcard entry
	{0, NewEntry("com", false, "", "")},      // test that this is not added as it is a duplicate
	{0, NewEntry("com", false, "/path", "")}, // test that this is not added as it is superceded by path
}

var testingSites = []struct {
	URL   string
	Check bool
}{
	{"http://www.google.com", true},
	{"https://www.google.com", true},
	{"http://child.www.google.com", true},
	{"https://child.www.google.com", true},
	{"http://google.com", true},
	{"http://google.com?query=true", true},
	{"http://google.com/?query=true", true},
	{"http://www.google.company", false},
	{"https://www.google.company", false},
	{"http://child.www.google.company", false},
	{"https://child.www.google.company", false},
	{"http://google.company", false},
	{"http://google.company?query=true", false},
	{"http://google.company/?query=true", false},
	{"http://path.com/path?query=true", true},
	{"http://path.com/path/?query=true", true},
	{"http://www.path.com/path?query=true", false},
	{"http://www.path.com/path/?query=true", false},
	{"http://path.com/path/good?query=true", true},
	{"https://path.com/path/good?query=true", true},
	{"http://path.com/path/good/?query=true", true},
	{"http://path.com/falsepath?query=true", false},
	{"http://path.com/falsepath/?query=true", false},
	{"http://path.com/falsepath/", false},
	{"http://path.com/falsepath", false},
	{"http://path.com/pathfalse?query=true", false},
	{"http://path.com/pathfalse/?query=true", false},
	{"http://path.com/pathfalse/", false},
	{"http://path.com/pathfalse", false},
	{"http://path.com/", false},
	{"http://path.com", false},
	{"http://travis-ci.org", true},
	{"https://travis-ci.org", true},
	{"http://www.travis-ci.org", false},
	{"http://www.mdlottery.com", false},
}

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
			result := wlm.Check(u)
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
