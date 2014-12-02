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

var patterns = []Entry{
	NewEntry("google.com", true, "", ""),
	NewEntry("path.com", false, "/path", ""),
	NewEntry("travis-ci.org", false, "", ""),
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
}

func BenchmarkTiedotManagerMatching(b *testing.B) {
	b.StopTimer()
	twm := NewTiedotWhitelistManager("temp")
	defer func() {
		twm.myDB.Close()
		os.RemoveAll("temp")
	}()
	benchManager(twm, b)
	b.StopTimer()
}

func BenchmarkRegexManagerMatching(b *testing.B) {
	b.StopTimer()
	rwm := NewRegexWhitelistManager("tempreg")
	defer func() {
		rwm.myDB.Close()
		os.RemoveAll("temp")
	}()
	benchManager(rwm, b)
	b.StopTimer()
}

func benchManager(wlm WhiteListManager, b *testing.B) {
	fmt.Println()
	b.StartTimer()
	for _, p := range patterns {
		wlm.Add(p)
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
