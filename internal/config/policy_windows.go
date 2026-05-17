//go:build windows

package config

import (
	"golang.org/x/sys/windows/registry"
)

const policyKey = `SOFTWARE\Policies\laplaque\AiProxy`

// loadPolicy reads Group Policy values from HKLM\SOFTWARE\Policies\laplaque\AiProxy
// and overrides cfg fields. Values shipped by the ADMX template:
//
//	Enabled  REG_DWORD  (informational only — no behaviour gate today)
//	Address  REG_SZ     → BindAddress
//	Port     REG_DWORD  → ProxyPort
//
// Group Policy takes precedence over both proxy-config.json and env vars.
func loadPolicy(cfg *Config) {
	applyPolicy(cfg, openMachinePolicy())
}

func openMachinePolicy() registryGetter {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE)
	if err != nil {
		return nil // policy key absent on unmanaged hosts; not an error
	}
	return &winRegistryGetter{k: k}
}

type winRegistryGetter struct {
	k registry.Key
}

func (g *winRegistryGetter) GetString(name string) (string, bool) {
	v, _, err := g.k.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return v, true
}

func (g *winRegistryGetter) GetUint64(name string) (uint64, bool) {
	v, _, err := g.k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (g *winRegistryGetter) Close() {
	_ = g.k.Close()
}
