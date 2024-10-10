package ip

import (
	"net"
	"testing"
)

func TestIsIPv6(t *testing.T) {
	testCases := []struct {
		addr     net.IP
		expected bool
	}{
		{net.ParseIP("::1"), true},
		{net.ParseIP("1234::4321"), true},
		{net.ParseIP("1234:5678:9abc:def0:1234:5678:9abc:def0"), true},
		{net.ParseIP("192.168.1.1"), false},
		{net.ParseIP("invalid"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.addr.String(), func(t *testing.T) {
			t.Parallel()
			if got := isIPv6(tc.addr); got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestIsIPinNetwork(t *testing.T) {
	testCases := []struct {
		addr     string
		network  string
		prefix   int
		expected bool
	}{
		{"2001:db8::1", "2001:db8::", 0, true},
		{"2001:db8::1", "2001:db8::", 64, true},
		{"2001:db8::1", "2001:db8::4321", 64, true},
		{"2001:db8::1", "2001:abab::4321", 64, false},
		{"2001:db8::1", "2001:db8::", 128, false},
		{"aaaa:bbbb:cccc:dddd:1111:2222:3333:4444", "aaaa:bbbb:cccc:dddd:eeee:ffff:9999:8888", 64, true},
		{"aaaa:bbbb:cccc:dddd:1111:2222:3333:4444", "aaaa:ffff:cccc:dddd:eeee:ffff:9999:8888", 64, false},
		{"::1", "::2", DefaultNetworkPrefixIPv6, false},
		{"10.10.10.10", "10.10.20.20", 16, true},
		{"10.10.10.10", "10.10.20.20", 32, false},
	}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			t.Parallel()
			if got := isIPinNetwork(tc.addr, tc.network, tc.prefix); got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
