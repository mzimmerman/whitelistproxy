package main

import (
	"io/ioutil"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestZones(t *testing.T) {
	zoneBufs := []string{
		"{\"User\":\"ab\",\"Network\":\"10.10.10.0/24\",\"Whitelist\":\"ab.json\"}",
		"{\"User\":\"cd\",\"Network\":\"10.10.0.0/16\",\"Whitelist\":\"cd.json\"}",
		"{\"User\":\"\",\"Network\":\"0.0.0.0/0\",\"Whitelist\":\"guest.json\"}",
	}
	zones := []Zone{
		{User: "ab", Net: net.IPNet{IP: []byte{10, 10, 10, 0}, Mask: []byte{255, 255, 255, 0}}, Whitelist: "ab.json"},
		{User: "cd", Net: net.IPNet{IP: []byte{10, 10, 0, 0}, Mask: []byte{255, 255, 0, 0}}, Whitelist: "cd.json"},
		{User: "", Net: net.IPNet{IP: []byte{0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0}}, Whitelist: "guest.json"},
	}
	for x, buf := range zoneBufs {
		z := Zone{}
		err := (&z).UnmarshalJSON([]byte(buf))
		if err != nil {
			t.Errorf("%d - unexpected error - %v", x, err)
		}
		if want, got := zones[x], z; !reflect.DeepEqual(want, got) {
			t.Errorf("%d - wanted %#v, got %#v", x, want, got)
		}
	}
	iptests := []struct {
		ip   net.IP
		isin []bool
	}{
		{net.IP{10, 10, 10, 0}, []bool{true, true, true}},
		{net.IP{192, 168, 1, 1}, []bool{false, false, true}},
		{net.IP{1, 1, 1, 1}, []bool{false, false, true}},
		{net.IP{10, 10, 1, 1}, []bool{false, true, true}},
	}
	for x := range iptests {
		for y := range iptests[x].isin {
			if want, got := iptests[x].isin[y], zones[y].contains(iptests[x].ip); want != got {
				t.Errorf("want %t, got %t - ip %s in zone %s", want, got, iptests[x].ip, zones[y].Net)
			}
		}
	}
}

func TestZoneManager(t *testing.T) {
	ioutil.WriteFile("zonemanagertests/zm.json", []byte(`{"User":"cd.com","Network":"10.10.10.0/24","Whitelist":"zonemanagertests/ab.json"}
{"User":"ab.com","Network":"10.10.0.0/16","Whitelist":"zonemanagertests/cd.json"}
{"User":"","Network":"0.0.0.0/0","Whitelist":"zonemanagertests/guest.json"}
`), 666)
	ioutil.WriteFile("zonemanagertests/ab.json", []byte(`{"Host":"ab.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 666)
	ioutil.WriteFile("zonemanagertests/cd.json", []byte(`{"Host":"cd.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 666)
	ioutil.WriteFile("zonemanagertests/guest.json", []byte(`{"Host":"guest.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 666)
	zm, err := NewZoneManager("zonemanagertests/zm.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	testingSites := []struct {
		ip         net.IP
		url        string
		check      bool
		numEntries int
		numBlocks  int
		addSuccess bool
	}{
		{net.IP{10, 10, 10, 0}, "http://ab.com", true, 1, 0, false},
		{net.IP{10, 10, 10, 0}, "http://cd.com", false, 1, 1, true},
		{net.IP{10, 10, 10, 0}, "http://cd.com", true, 2, 0, false}, // blocked value reduced since site was whitelisted
		{net.IP{10, 10, 1, 0}, "http://ab.com", false, 1, 1, true},
		{net.IP{10, 10, 1, 0}, "http://cd.com", true, 2, 0, false}, // blocked value reduced since site was whitelisted
		{net.IP{10, 10, 1, 0}, "http://ab.com", true, 2, 0, false}, // blocked value reduced since site was whitelisted
		{net.IP{192, 168, 1, 1}, "http://guest.com", true, 1, 0, false},
		{net.IP{192, 168, 1, 1}, "http://fail.com", false, 1, 1, true},
		{net.IP{192, 168, 1, 1}, "http://fail.com", true, 2, 0, false}, // blocked value reduced since site was whitelisted
	}
	for j, s := range testingSites {
		u, _ := url.Parse(s.url)
		if want, got := s.check, zm.Check(s.ip, Site{URL: u}); want != got {
			t.Errorf("[%d] For URL %s - wanted %t, got %t", j, u, want, got)
		}
		if want, got := s.numBlocks, len(zm.RecentBlocks(s.ip, 50)); want != got {
			t.Errorf("[%d] - # of blocks wanted %v, got %v", j, want, got)
		}
		t.Logf("Current blocks are:")
		for _, block := range zm.RecentBlocks(s.ip, 50) {
			t.Log(block)
		}
		if want, got := s.numEntries, len(zm.Current(s.ip)); want != got {
			t.Errorf("[%d] - # of entries wanted %v, got %v", j, want, got)
		}
		t.Logf("Current entries are:")
		for _, entry := range zm.Current(s.ip) {
			t.Log(entry)
		}
		if !s.check { // we were blocked, add it to the whitelist
			err = zm.Add(s.ip, u.Host, NewEntry(u.Host, false, "", "", time.Second), true)
			if err != nil && s.addSuccess { // fail if there should not have been an error
				t.Errorf("%v", err)
			}
		}
	}
}
