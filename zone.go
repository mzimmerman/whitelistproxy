package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

type Zone struct {
	User      string                  // username to require for authentication
	Net       *net.IPNet              // nil means everything
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
	_, z.Net, err = net.ParseCIDR(tmp.Network)
	return err
}

func (z Zone) contains(ip net.IP) bool {
	return z.Net.Contains(ip)
}

func (zm ZoneManager) find(ip net.IP) *Zone { // returns nil on no match
	for x := range zm {
		if zm[x].contains(ip) {
			return zm[x]
		}
	}
	return nil
}

func (zm ZoneManager) Add(ip net.IP, user string, e Entry, authRequired bool) error {
	zone := zm.find(ip)
	if zone == nil {
		return fmt.Errorf("Network %s not found in any zone", ip)
	}
	if authRequired && user != zone.User {
		if user == "" {
			return fmt.Errorf("Please authenticate to add to the whitelist for network %s", zone.Net)
		}
		return fmt.Errorf("User %s not authorized to add site in network %s", user, ip)
	}
	zone.wlm.Add(ip, user, e, authRequired)
	return nil
}

func (zm ZoneManager) Check(ip net.IP, site Site) bool {
	zone := zm.find(ip)
	if zone == nil {
		return false // if no zones match, deny
	}
	return zone.wlm.Check(ip, site)
}

func (zm ZoneManager) RecentBlocks(ip net.IP, num int) []Site {
	zone := zm.find(ip)
	if zone == nil {
		return []Site{}
	}
	return zone.wlm.RecentBlocks(ip, num)
}

func (zm ZoneManager) Current(ip net.IP) []Entry {
	zone := zm.find(ip)
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
