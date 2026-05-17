//go:build !windows

package config

import "testing"

func TestLoadPolicy_NoOpOnNonWindows(t *testing.T) {
	cfg := defaults()
	originalPort := cfg.ProxyPort
	originalBind := cfg.BindAddress
	loadPolicy(cfg)
	if cfg.ProxyPort != originalPort {
		t.Errorf("loadPolicy changed ProxyPort on non-Windows: got %d, want %d", cfg.ProxyPort, originalPort)
	}
	if cfg.BindAddress != originalBind {
		t.Errorf("loadPolicy changed BindAddress on non-Windows: got %q, want %q", cfg.BindAddress, originalBind)
	}
}
