//go:build windows

package config

import (
	"log"

	"golang.org/x/sys/windows/registry"
)

const policyKey = `SOFTWARE\Policies\laplaque\AiProxy`

// loadPolicy reads Group Policy values from HKLM\SOFTWARE\Policies\laplaque\AiProxy
// and overrides cfg fields. Values shipped by the ADMX template:
//
//	Enabled    REG_DWORD  (informational only)
//	Address    REG_SZ     → BindAddress
//	Port       REG_DWORD  → ProxyPort
//	BypassList REG_SZ     → UpstreamProxy bypass (joined into UpstreamProxy as informational)
//
// Group Policy takes precedence over both proxy-config.json and env vars.
func loadPolicy(cfg *Config) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE)
	if err != nil {
		return // policy key absent on unmanaged hosts; not an error
	}
	defer func() { _ = k.Close() }()

	if addr, _, err := k.GetStringValue("Address"); err == nil && addr != "" {
		cfg.BindAddress = addr
	}
	if port, _, err := k.GetIntegerValue("Port"); err == nil && port > 0 && port <= 65535 {
		cfg.ProxyPort = int(port)
	}
	if bypass, _, err := k.GetStringValue("BypassList"); err == nil && bypass != "" {
		// Recorded for log/diagnostics; the Go binary's HTTP_PROXY/NO_PROXY
		// handling already covers actual bypass routing.
		log.Printf("[CONFIG] Group Policy BypassList = %q", bypass)
	}
}
