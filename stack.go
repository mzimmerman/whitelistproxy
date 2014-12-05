package main

import "sync"

type Stack struct {
	top  *element
	size int
	Max  int
	sync.RWMutex
}

type element struct {
	value Site
	next  *element
}

// Return the stack's length
func (s *Stack) Len() int {
	s.RLock()
	defer s.RUnlock()
	return s.size
}

// Push a new element onto the stack
func (s *Stack) Push(site Site) {
	s.Lock()
	defer s.Unlock()
	s.top = &element{site, s.top}
	s.size++
	if s.Max > 0 && s.size > s.Max {
		walker := s.top
		for {
			if walker.next.next == nil {
				walker.next = nil
				s.size--
				return
			}
			walker = walker.next
		}
	}
}

// Remove the top element from the stack and return it's value
// If the stack is empty, return nil
func (s *Stack) Pop() (site Site) {
	s.Lock()
	defer s.Unlock()
	if s.size > 0 {
		site, s.top = s.top.value, s.top.next
		s.size--
	}
	return
}
