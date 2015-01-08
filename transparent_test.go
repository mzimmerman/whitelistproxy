package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"
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

func TestSupercedes(t *testing.T) {
	patterns := []Entry{
		/*0*/ NewEntry("www.google.com", false, "", "", -time.Hour),
		/*1*/ NewEntry("www.google.com", true, "", "", -time.Minute),
		/*2*/ NewEntry("other.google.com", true, "", "", -time.Second),
		/*3*/ NewEntry("google.com", true, "", "", -time.Millisecond),
		/*4*/ NewEntry("explicit.google.com", false, "", "", 0),
		/*5*/ NewEntry("wildcard.google.com", true, "", "", 0),
		/*6*/ NewEntry("path.com", false, "/path", "", time.Millisecond),
		/*7*/ NewEntry("path.com", false, "/path/too", "", time.Second),
		/*8*/ NewEntry("travis-ci.org", false, "", "", time.Minute),
		/*9*/ NewEntry("com", true, "", "", time.Hour), // this in invalid input, use NewEntry to "clean" it and make it a non-wildcard entry
		/*10*/ NewEntry("com", false, "", "", time.Hour*24), // test that this is not added as it is a duplicate
		/*11*/ NewEntry("com", false, "/path", "", time.Hour*50), // test that this is not added as it is superceded by path
	}
	pathAnswers := [][]bool{
		// ------------0----1-------2-------3-----4-------5------6------7------8------9-----10-----11
		/*0*/ []bool{true, false, false, false, false, false, false, false, false, false, false, false},
		/*1*/ []bool{true, true, false, false, false, false, false, false, false, false, false, false},
		/*2*/ []bool{false, false, true, false, false, false, false, false, false, false, false, false},
		/*3*/ []bool{true, true, true, true, true, true, false, false, false, false, false, false},
		/*4*/ []bool{false, false, false, false, true, false, false, false, false, false, false, false},
		/*5*/ []bool{false, false, false, false, false, true, false, false, false, false, false, false},
		/*6*/ []bool{false, false, false, false, false, false, true, true, false, false, false, false},
		/*7*/ []bool{false, false, false, false, false, false, false, true, false, false, false, false},
		/*8*/ []bool{false, false, false, false, false, false, false, false, true, false, false, false},
		/*9*/ []bool{false, false, false, false, false, false, false, false, false, true, true, true},
		/*10*/ []bool{false, false, false, false, false, false, false, false, false, true, true, true},
		/*11*/ []bool{false, false, false, false, false, false, false, false, false, false, false, true}}
	timeAnswers := [][]bool{
		// ------------0----1-------2-------3-----4-------5------6------7------8------9-----10-----11
		/*0*/ []bool{true, false, false, false, false, false, false, false, false, false, false, false},
		/*1*/ []bool{true, true, false, false, false, false, false, false, false, false, false, false},
		/*2*/ []bool{true, true, true, false, false, false, false, false, false, false, false, false},
		/*3*/ []bool{true, true, true, true, false, false, false, false, false, false, false, false},
		/*4*/ []bool{true, true, true, true, true, true, true, true, true, true, true, true},
		/*5*/ []bool{true, true, true, true, true, true, true, true, true, true, true, true},
		/*6*/ []bool{true, true, true, true, false, false, true, false, false, false, false, false},
		/*7*/ []bool{true, true, true, true, false, false, true, true, false, false, false, false},
		/*8*/ []bool{true, true, true, true, false, false, true, true, true, false, false, false},
		/*9*/ []bool{true, true, true, true, false, false, true, true, true, true, false, false},
		/*10*/ []bool{true, true, true, true, false, false, true, true, true, true, true, false},
		/*11*/ []bool{true, true, true, true, false, false, true, true, true, true, true, true},
	}
	for x := range timeAnswers {
		for y := range timeAnswers[x] {
			if expected, got := timeAnswers[x][y], patterns[x].timeSupercedes(patterns[y]); expected != got {
				if expected {
					t.Errorf("TIME: Expected %d to supercede %d", x, y)
				} else {
					t.Errorf("TIME: Did not expect %d to supercede %d", x, y)
				}
			}
			if expected, got := pathAnswers[x][y], patterns[x].pathSupercedes(patterns[y]); expected != got {
				if expected {
					t.Errorf("PATH: Expected %d to supercede %d", x, y)
				} else {
					t.Errorf("PATH: Did not expect %d to supercede %d", x, y)
				}
			}
		}
	}
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
		whitelistService(req, nil)
		if w.Code != http.StatusOK {
			t.Errorf("Error displaying %s - %s", n, w.Body.String())
		}
	}
}
