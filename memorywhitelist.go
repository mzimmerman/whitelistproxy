package main

import (
	"encoding/csv"
	"io"
	"log"
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
	writer  *csv.Writer
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
	twm := &MemoryWhitelistManager{
		stack: NewStack(50),
	}
	r := csv.NewReader(tmp)
	for {
		val, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.ANSIC, val[4])
		twm.add(Entry{
			Host:            val[0],
			MatchSubdomains: val[1] == "true",
			Path:            val[2],
			Creator:         val[3],
			Created:         t,
		}, false)
	}
	err = tmp.Close()
	if err != nil {
		return nil, err
	}
	twm.file, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	twm.writer = csv.NewWriter(twm.file)
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
		current := twm.entries[i]
		if current.Host == proposed.Host {
			if current.MatchSubdomains == proposed.MatchSubdomains {
				if proposed.MatchSubdomains == false && strings.HasPrefix(proposed.Path+"/", current.Path+"/") {
					// superseded entry, return no changes
					return 0
				}
				if current.MatchSubdomains == false && strings.HasPrefix(current.Path+"/", proposed.Path+"/") {
					returnVal = removeEntry(returnVal)
					twm.entries[i], twm.entries = twm.entries[len(twm.entries)-1], twm.entries[:len(twm.entries)-1]
					i--
					continue
				}
				if current.MatchSubdomains && proposed.MatchSubdomains {
					// duplicate entry, return no changes
					return 0
				}
			}
			// current.MatchSubdomains != proposed.MatchSubdomains
			if !current.MatchSubdomains {
				returnVal = removeEntry(returnVal)
				twm.entries[i], twm.entries = twm.entries[len(twm.entries)-1], twm.entries[:len(twm.entries)-1]
				i--
				continue
			}
		} else if current.MatchSubdomains && strings.HasSuffix(proposed.Host, "."+current.Host) {
			// superseded entry, return no changes
			return 0
		} else if proposed.MatchSubdomains && strings.HasSuffix(current.Host, "."+proposed.Host) {
			returnVal = removeEntry(returnVal)
			twm.entries[i], twm.entries = twm.entries[len(twm.entries)-1], twm.entries[:len(twm.entries)-1]
			i--
			continue
		}
	}
	if returnVal != 0 { // if entities are removed or need to be added only, lets add it
		twm.entries = append(twm.entries, proposed)
		twm.cleanStack(proposed)
	}
	if writeToDisk {
		twm.writer.Write(proposed.CSV())
		twm.writer.Flush()
		log.Printf("MWLM added entry %#v", proposed)
	}
	return returnVal
}

func (twm *MemoryWhitelistManager) Add(entry Entry) {
	twm.Lock()
	defer twm.Unlock()
	twm.add(entry, true)
}

func (twm *MemoryWhitelistManager) Check(site Site) bool {
	twm.RLock()
	defer twm.RUnlock()
	result := twm.internalCheck(site)
	if !result {
		twm.stack.Push(site)
	}
	return result
}

func (twm *MemoryWhitelistManager) internalCheck(site Site) bool {
	for _, x := range twm.entries {
		if site.URL.Host == x.Host {
			if x.Path == "" {
				return true
			}
			if strings.HasPrefix(site.URL.Path, x.Path) {
				if len(site.URL.Path) == len(x.Path) { // exact same path since prefix passes
					return true
				}
				// u.Path must be at least one character longer since prefix passes and they're not equal
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

func (twm *MemoryWhitelistManager) RecentBlocks(limit int) []Site {
	list := make([]Site, 0, twm.stack.Len())
	for {
		if len(list) == limit {
			break
		}
		elem := twm.stack.Pop()
		if elem == nil {
			break
		}
		list = append(list, *elem)
	}
	return list
}

func (twm *MemoryWhitelistManager) Current() []Entry {
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
