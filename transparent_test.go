package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestTemplates(t *testing.T) {
	fmt.Println()
	twm, err := NewMemoryWhitelistManager("tempmem.csv")
	if err != nil {
		t.Fatalf("Error starting memory whitelist manager - %t", err)
	}
	defer func() {
		twm.file.Close()
		os.RemoveAll("tempmem.csv")
	}()
	for _, p := range patterns {
		wlm.Add(p.e)
	}
	for j, s := range testingSites {
		u, _ := url.Parse(s.URL)
		result := wlm.Check(Site{URL: u, Referer: s.Referer})
		if result != s.Check {
			t.Errorf("[%d] For URL %s - expected %t, got %t", j, u, s.Check, result)
		}
	}
	templates := []string{
		"/auth",
		"/list",
		"/current",
	}
	for _, n := range templates {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("get", n, nil)
		whitelistService(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Error displaying %s - %s", n, w.Body.String())
		}
	}
}
