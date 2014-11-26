package main

import (
	"net/url"
)

type Stack struct {
	top  *element
	size int
	Max  int
}

type element struct {
	value *url.URL // All types satisfy the empty interface, so we can store anything here.
	next  *element
}

// Return the stack's length
func (s *Stack) Len() int {
	return s.size
}

// Push a new element onto the stack
func (s *Stack) Push(value *url.URL) {
	s.top = &element{value, s.top}
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
func (s *Stack) Pop() (value *url.URL) {
	if s.size > 0 {
		value, s.top = s.top.value, s.top.next
		s.size--
		return
	}
	return nil
}
