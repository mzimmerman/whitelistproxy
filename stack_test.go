package main

import (
	"net/url"
	"testing"
)

func pushAll(s *Stack, data []*url.URL) {
	for _, x := range data {
		s.Push(x)
	}
}

func TestStack(t *testing.T) {
	testData := []string{
		"google.com",
		"helpme.com",
		"github.com",
		"other",
		"testme:8080",
	}
	urls := make([]*url.URL, len(testData))
	for x := range testData {
		urls[x], _ = url.Parse(testData[x])
	}
	s := &Stack{
		Max: 2,
	}
	pushAll(s, urls)
	if want, got := 2, s.Len(); got != want {
		t.Errorf("Wanted %v, got %v", want, got)
	}
	if want, got := urls[4], s.Pop(); got != want {
		t.Errorf("Wanted %v, got %v", want, got)
	}
	if want, got := urls[3], s.Pop(); got != want {
		t.Errorf("Wanted %v, got %v", want, got)
	}
	if want, got := 0, s.Len(); got != want {
		t.Errorf("Wanted %v, got %v", want, got)
	}
}