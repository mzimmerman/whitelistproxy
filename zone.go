package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type Zone struct {
	User      string                  // username to require for authentication
	Net       net.IPNet               // nil means everything
	Whitelist string                  // filename of whitelist
	wlm       *MemoryWhitelistManager `json:"-"`
}

func (z *Zone) UnmarshalJSON(data []byte) error {
	var tmp struct {
		User      string
		Network   string
		Whitelist string
	}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	z.User = tmp.User
	z.Whitelist = tmp.Whitelist
	_, tmpNet, err := net.ParseCIDR(tmp.Network)
	z.Net = *tmpNet
	return err
}

func (z Zone) contains(ip net.IP) bool {
	return z.Net.Contains(ip)
}

func (zm ZoneManager) Find(ip net.IP) *Zone { // returns nil on no match
	for x := range zm {
		if zm[x].contains(ip) {
			return zm[x]
		}
	}
	return nil
}

type AuthenticationError string
type AuthorizationError string
type NoMatchingZone string

func (nmz NoMatchingZone) Error() string {
	return string(nmz)
}

func (ae AuthenticationError) Error() string {
	return string(ae)
}

func (ae AuthorizationError) Error() string {
	return string(ae)
}

func (zm ZoneManager) Add(ip net.IP, user string, e Entry, authRequired bool) error {
	zone := zm.Find(ip)
	if zone == nil {
		return NoMatchingZone(fmt.Sprintf("Network %s not found in any zone", ip))
	}
	if authRequired {
		if user == "" {
			return AuthenticationError(fmt.Sprintf("Authentication is required to add a site in network %s", zone.Net))
		}
		found := zone.User == ""
		authorizedUsers := strings.Split(zone.User, ",")
		for _, au := range authorizedUsers {
			if au == user {
				found = true
				break
			}
		}
		if !found {
			return AuthorizationError(fmt.Sprintf("User %s not authorized to add site in network %s, only one of [%s] is allowed", user, zone.Net, zone.User))
		}
	}
	zone.wlm.Add(ip, user, e, authRequired)
	return nil
}

func (zm ZoneManager) Check(ip net.IP, site Site) (bool, bool) {
	zone := zm.Find(ip)
	if zone == nil {
		return false, false // if no zones match, deny
	}
	// err can occur when no port # is found, host is empty string in that case
	host, port, err := net.SplitHostPort(site.URL.Host)
	if err == nil {
		site.URL.Host = host
	}
	if port != "" {
		portNum, err := strconv.Atoi(port)
		if err != nil {
			log.Printf("Invalid port number - %s - %v", port, err)
			return false, false
		}
		if portNum != 80 && portNum != 443 {
			log.Printf("This proxy only supports traffic on port 80 and 443")
			return false, false
		}
	}
	return zone.wlm.Check(ip, site)
}

func (zm ZoneManager) RecentBlocks(ip net.IP, num int) []Site {
	zone := zm.Find(ip)
	if zone == nil {
		return []Site{}
	}
	return zone.wlm.RecentBlocks(ip, num)
}

func (zm ZoneManager) Current(ip net.IP) []Entry {
	zone := zm.Find(ip)
	if zone == nil {
		return []Entry{} // if no zones match, return an empty list
	}
	return zone.wlm.Current(ip)
}

type ZoneManager []*Zone

func NewZoneManager(filename string) (ZoneManager, error) {
	zm := make(ZoneManager, 0, 8) // optimize for 8 zones
	tmp, err := os.Open(filename)
	if err != nil {
		return zm, err
	}
	r := bufio.NewReader(tmp)
	for {
		val, err := r.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return zm, err
		}
		zone := Zone{}
		err = json.Unmarshal(val, &zone)
		if err != nil {
			log.Printf("Error reading input - %s", val)
			return zm, err
		}
		zone.wlm, err = NewMemoryWhitelistManager(zone.Whitelist)
		if err != nil {
			return zm, err
		}
		zm = append(zm, &zone)
	}
	return zm, nil
}
