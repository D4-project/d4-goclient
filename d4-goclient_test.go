package main

import (
	"testing"
)

var testCases = []struct {
	name     string
	str      string
	expected bool
}{
	{"Well-formed IPv4 with port", "127.0.0.1:4443", true},
	{"Well-formed IPv4 without port", "127.0.0.1", false},
	{"Malformed IPv4 with port", "127..0.1:4443", false},
	{"Malformed IPv4 without port", "127..0.1", false},
	{"Well-formed IPv6 with port - 2", "[::1]:4443", true},
	{"Well-formed IPv6 without port", "[fe80::1%25en0]", false},
	{"Malformed IPv6 with port", "[::::1]:4443", false},
	{"Malformed IPv6 without port", "[::::::::1]", false},
	{"Malformed IPv6 : missing square brackets", "::::::::1:4443", false},
	{"Well-formed DNS name with port", "toto.circl.lu:4443", true},
	{"Well-formed DNS name without port", "toto.circl.lu", false},
	{"Malformed DNS name with port", ".:4443", false},
}

func TestIsNet(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := isNet(tc.str)
			if b != tc.expected {
				t.Fail()
			}
		})
	}
}
