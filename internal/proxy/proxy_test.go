package proxy

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// Private ranges
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.1.100", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"169.254.1.1", true},
		{"::1", true},

		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.32.0.1", false},
		{"192.169.0.1", false},
		{"11.0.0.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP: %s", tt.ip)
		}
		if got := isPrivateIP(ip); got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestIsPrivateHost_Literal(t *testing.T) {
	tests := []struct {
		host    string
		private bool
	}{
		{"127.0.0.1:8080", true},
		{"10.0.0.1", true},
		{"192.168.1.1:443", true},
		{"8.8.8.8:53", false},
		{"8.8.8.8", false},
	}
	for _, tt := range tests {
		if got := isPrivateHost(tt.host); got != tt.private {
			t.Errorf("isPrivateHost(%q) = %v, want %v", tt.host, got, tt.private)
		}
	}
}
