package config

// registryGetter is the read-side of a Windows registry key — abstracted so
// the policy-apply logic can be unit-tested on any platform with a stub.
// A nil getter means "policy key is absent"; applyPolicy treats that as a
// no-op rather than an error.
type registryGetter interface {
	GetString(name string) (string, bool)
	GetUint64(name string) (uint64, bool)
	Close()
}

// applyPolicy overlays Group Policy values from g onto cfg. Order matches
// the doc comment on loadPolicy: Address overrides BindAddress, Port
// overrides ProxyPort. Empty / out-of-range values are ignored.
//
// Group Policy wins over both proxy-config.json and env vars; this function
// is called last in config.Load.
func applyPolicy(cfg *Config, g registryGetter) {
	if g == nil {
		return
	}
	defer g.Close()

	if addr, ok := g.GetString("Address"); ok && addr != "" {
		cfg.BindAddress = addr
	}
	if port, ok := g.GetUint64("Port"); ok && port > 0 && port <= 65535 {
		cfg.ProxyPort = int(port)
	}
}
