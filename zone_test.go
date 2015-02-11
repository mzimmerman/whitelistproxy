package main

import (
	"io/ioutil"
	"net"
	"net/url"
	"reflect"
	"testing"
)

func TestZones(t *testing.T) {
	zoneBufs := []string{
		"{\"User\":\"ab\",\"Network\":\"10.10.10.0/24\",\"Whitelist\":\"ab.json\"}",
		"{\"User\":\"cd\",\"Network\":\"10.10.0.0/16\",\"Whitelist\":\"cd.json\"}",
		"{\"User\":\"\",\"Network\":\"172.16.0.0/12\",\"Whitelist\":\"guest.json\"}",
	}
	zones := []Zone{
		{User: "ab", Net: net.IPNet{IP: []byte{10, 10, 10, 0}, Mask: []byte{255, 255, 255, 0}}, Whitelist: "ab.json"},
		{User: "cd", Net: net.IPNet{IP: []byte{10, 10, 0, 0}, Mask: []byte{255, 255, 0, 0}}, Whitelist: "cd.json"},
		{User: "", Net: net.IPNet{IP: []byte{172, 16, 0, 0}, Mask: []byte{255, 240, 0, 0}}, Whitelist: "guest.json"},
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
		{net.IP{10, 10, 10, 0}, []bool{true, true, false}},
		{net.IP{192, 168, 1, 1}, []bool{false, false, false}},
		{net.IP{1, 1, 1, 1}, []bool{false, false, false}},
		{net.IP{10, 10, 1, 1}, []bool{false, true, false}},
		{net.IP{172, 16, 1, 1}, []bool{false, false, true}},
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
	ioutil.WriteFile("zonemanagertests/zm.json", []byte(`{"User":"ab","Network":"10.10.10.0/24","Whitelist":"zonemanagertests/ab.json"}
{"User":"cd","Network":"10.10.0.0/16","Whitelist":"zonemanagertests/cd.json"}
{"User":"","Network":"10.0.0.0/8","Whitelist":"zonemanagertests/guest.json"}
{"User":"one,two,three","Network":"172.16.0.0/12","Whitelist":"zonemanagertests/multiple.json"}
`), 0666)
	ioutil.WriteFile("zonemanagertests/ab.json", []byte(`{"Host":"ab.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 0666)
	ioutil.WriteFile("zonemanagertests/cd.json", []byte(`{"Host":"cd.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 0666)
	ioutil.WriteFile("zonemanagertests/guest.json", []byte(`{"Host":"guest.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 0666)
	ioutil.WriteFile("zonemanagertests/multiple.json", []byte(`{"Host":"multiple.com","MatchSubdomains":false,"Path":"","Creator":"","Created":"2015-02-02T09:19:19.195701657-05:00","Expires":"2015-02-02T09:19:19.195701657-05:00"}
`), 0666)

	zm, err := NewZoneManager("zonemanagertests/zm.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	testingSites := []struct {
		ip        net.IP
		url       string
		check     bool
		numBlocks int
	}{
		{net.IP{10, 10, 10, 0}, "http://ab.com", true, 0},
		{net.IP{10, 10, 10, 0}, "http://cd.com", false, 1},
		{net.IP{10, 10, 1, 0}, "http://ab.com", false, 1},
		{net.IP{10, 10, 1, 0}, "http://cd.com", true, 1},
		{net.IP{10, 168, 1, 1}, "http://guest.com", true, 0},
		{net.IP{10, 168, 1, 1}, "http://guest.com:80", true, 0},
		{net.IP{10, 168, 1, 1}, "http://guest.com:443", true, 0},
		{net.IP{10, 168, 1, 1}, "http://guest.com:2000", false, 0},
		{net.IP{10, 168, 1, 1}, "http://fail.com", false, 1},
		{net.IP{172, 16, 1, 1}, "http://fail.com", false, 1},
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
		t.Logf("Current entries are:")
		for _, entry := range zm.Current(s.ip) {
			t.Log(entry)
		}
	}
	testingAdds := []struct {
		ip          net.IP
		user        string
		requireAuth bool
		err         error
	}{
		{net.IP{1, 1, 1, 1}, "", true, NoMatchingZone("")},
		{net.IP{1, 1, 1, 1}, "", false, NoMatchingZone("")},
		{net.IP{10, 1, 1, 1}, "", false, nil},                    // no user auth requirements
		{net.IP{10, 1, 1, 1}, "", true, AuthenticationError("")}, // User's required to be authenticated, but no listed users
		{net.IP{10, 10, 1, 1}, "", true, AuthenticationError("")},
		{net.IP{10, 10, 1, 1}, "wronguser", true, AuthorizationError("")},
		{net.IP{10, 10, 1, 1}, "cd", true, nil},
		{net.IP{172, 16, 1, 1}, "two", true, nil},
	}
	for x, ta := range testingAdds {
		err = zm.Add(ta.ip, ta.user, NewEntry("host.com", false, "", "", 0), ta.requireAuth)
		switch ta.err.(type) {
		case NoMatchingZone:
			if _, ok := err.(NoMatchingZone); !ok {
				t.Errorf("[%d] - expected NoMatchingZoneError - %v", x, err)
			}
		case AuthenticationError:
			if _, ok := err.(AuthenticationError); !ok {
				t.Errorf("[%d] - expected AuthenticationError - %v", x, err)
			}
		case AuthorizationError:
			if _, ok := err.(AuthorizationError); !ok {
				t.Errorf("[%d] - expected AuthorizationError - %v", x, err)
			}
		default:
			if err != nil {
				t.Errorf("[%d] - expected nil, got %v", x, err)
			}
		}
	}
}
