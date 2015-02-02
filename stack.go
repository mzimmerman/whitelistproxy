package main

import "sync"

func NewStack(max int) *Stack {
	return &Stack{
		elements: make([]Site, max),
	}
}

type Stack struct {
	elements []Site
	newest   int // inclusive
	length   int
	sync.RWMutex
}

func (s *Stack) Len() int {
	s.RLock()
	defer s.RUnlock()
	return s.length
}

// Push a new element onto the stack
func (s *Stack) Push(site Site) {
	s.Lock()
	defer s.Unlock()
	s.newest++
	if s.newest == cap(s.elements) {
		s.newest = 0
	}
	s.elements[s.newest] = site
	if s.length < cap(s.elements) {
		s.length++
	}
}

// Return the (num) most recently blocked sites
func (s *Stack) View(num int) (sites []Site) {
	s.Lock()
	defer s.Unlock()
	if s.length == 0 {
		return sites
	}
	if s.length < num {
		num = s.length
	}
	sites = make([]Site, num)
	walker := s.newest
	for x := range sites {
		sites[x] = s.elements[walker]
		walker--
		if walker == -1 {
			walker = cap(s.elements) - 1
		}
	}
	return sites
}

// Remove the top element from the stack and return it's value
// If the stack is empty, return nil
func (s *Stack) Pop() (site *Site) {
	s.Lock()
	defer s.Unlock()
	if s.length == 0 {
		return nil
	}
	s.length--
	victim := s.elements[s.newest]
	s.newest--
	if s.newest == -1 {
		s.newest = cap(s.elements) - 1
	}
	return &victim
}
