package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type MemoryWhitelistManager struct {
	sync.RWMutex
	entries []Entry
	stack   *Stack
	writer  *bufio.Writer
	file    *os.File
}

func NewMemoryWhitelistManager(filename string) (*MemoryWhitelistManager, error) {
	tmp, err := os.Open(filename)
	if os.IsNotExist(err) {
		tmp, err = os.Create(filename)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		err := tmp.Close()
		if err != nil {
			log.Printf("Error closing file - %v", err)
		}
	}()
	twm := &MemoryWhitelistManager{
		stack: NewStack(50),
	}
	r := bufio.NewReader(tmp)
	for {
		val, err := r.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entry := Entry{}
		err = json.Unmarshal(val, &entry)
		if err != nil {
			log.Printf("Error reading input - %s", val)
			continue
		}
		twm.add(entry, false)
	}
	twm.file, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	twm.writer = bufio.NewWriter(twm.file)
	return twm, nil
}

func removeEntry(returnVal int) int {
	if returnVal == 1 {
		returnVal = -1
	} else {
		returnVal--
	}
	return returnVal
}

// returns 1 if one entry was added and 0 removed
// returns 0 if no entries added or removed
// returns a negative integer for all entries removed (when one is added to supersede them)
func (twm *MemoryWhitelistManager) add(proposed Entry, writeToDisk bool) int {
	returnVal := 1
	// returnVal starts under the assumption that the entry should be added
	// once it finds reasons otherwise, it negates it properly
	// if returnVal is 0 at the end, don't add the entry
	for i := 0; i < len(twm.entries); i++ {
		if twm.entries[i].Supercedes(proposed) {
			return 0
		}
		if proposed.Supercedes(twm.entries[i]) {
			returnVal = removeEntry(returnVal)
			twm.entries[i], twm.entries = twm.entries[len(twm.entries)-1], twm.entries[:len(twm.entries)-1]
			i--
		}
	}
	twm.entries = append(twm.entries, proposed)
	twm.cleanStack(proposed)
	if writeToDisk {
		serialized, err := json.Marshal(proposed)
		if err != nil {
			log.Printf("Unable to serialize entry %v - %v", proposed, err)
		} else {
			twm.writer.Write(serialized)
			twm.writer.Write([]byte{'\n'})
			twm.writer.Flush()
		}
	}
	log.Printf("MWLM added entry %#v", proposed)
	return returnVal
}

func (twm *MemoryWhitelistManager) Add(ip net.IP, user string, entry Entry, authRequired bool) error {
	if authRequired && user == "" {
		return fmt.Errorf("Please authenticate to add to the whitelist")
	}
	twm.Lock()
	defer twm.Unlock()
	twm.add(entry, true)
	return nil
}

func (twm *MemoryWhitelistManager) Check(ip net.IP, site Site) bool {
	twm.RLock()
	defer twm.RUnlock()
	result := twm.internalCheck(site)
	if !result && site.Referer != "pressl" {
		refererURL, err := url.Parse(site.Referer)
		if err == nil && twm.internalCheck(Site{URL: refererURL}) {
			return true
		}
		twm.stack.Push(site)
	}
	return result
}

func (twm *MemoryWhitelistManager) internalCheck(site Site) bool {
	now := time.Now()
	for _, x := range twm.entries {
		if x.Expired(now) {
			continue
		}
		if site.URL.Host == x.Host {
			if x.Path == "" {
				return true
			}
			if strings.HasPrefix(site.URL.Path, x.Path) {
				if len(site.URL.Path) == len(x.Path) { // exact same path since prefix passes
					return true
				}
				// x.Path must be at least one character longer since prefix passes and they're not equal
				if site.URL.Path[len(x.Path)] == '?' || site.URL.Path[len(x.Path)] == '/' {
					return true
				}
			}
		}
		if x.MatchSubdomains && strings.HasSuffix(site.URL.Host, "."+x.Host) {
			return true
		}
	}
	return false // no matches found
}

type Site struct {
	URL     *url.URL
	Referer string // using the "historical" spelling :)
}

func (twm *MemoryWhitelistManager) RecentBlocks(ip net.IP, limit int) []Site {
	return twm.stack.View(limit)
}

func (twm *MemoryWhitelistManager) Current(ip net.IP) []Entry {
	twm.Lock()
	defer twm.Unlock()
	return twm.entries
}

func (twm *MemoryWhitelistManager) cleanStack(newEntry Entry) {
	sites := make([]Site, twm.stack.Len())
	for i := range sites {
		sites[i] = *twm.stack.Pop()
	}
	for i := len(sites) - 1; i >= 0; i-- {
		if !twm.internalCheck(sites[i]) { // if it is still not allowed, push it back
			twm.stack.Push(sites[i])
		}
	}
}
