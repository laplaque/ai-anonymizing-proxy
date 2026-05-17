//go:build !windows

package config

// loadPolicy is a no-op on non-Windows platforms. The Windows build reads
// HKLM\SOFTWARE\Policies\laplaque\AiProxy and merges values here.
func loadPolicy(_ *Config) {}
