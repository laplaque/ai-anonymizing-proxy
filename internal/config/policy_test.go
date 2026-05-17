package config

import "testing"

// fakeRegistry stands in for an HKLM key in tests so the Group Policy
// override logic is reachable from any platform.
type fakeRegistry struct {
	strings map[string]string
	ints    map[string]uint64
	closed  bool
}

func (f *fakeRegistry) GetString(name string) (string, bool) {
	v, ok := f.strings[name]
	return v, ok
}

func (f *fakeRegistry) GetUint64(name string) (uint64, bool) {
	v, ok := f.ints[name]
	return v, ok
}

func (f *fakeRegistry) Close() { f.closed = true }

func TestApplyPolicy_NilGetter_NoOp(t *testing.T) {
	cfg := defaults()
	origPort, origBind := cfg.ProxyPort, cfg.BindAddress
	applyPolicy(cfg, nil)
	if cfg.ProxyPort != origPort || cfg.BindAddress != origBind {
		t.Fatalf("nil getter changed cfg: port %d bind %q", cfg.ProxyPort, cfg.BindAddress)
	}
}

func TestApplyPolicy_OverridesAddressAndPort(t *testing.T) {
	cfg := defaults()
	g := &fakeRegistry{
		strings: map[string]string{"Address": "0.0.0.0"},
		ints:    map[string]uint64{"Port": 18080},
	}
	applyPolicy(cfg, g)
	if cfg.BindAddress != "0.0.0.0" {
		t.Errorf("BindAddress = %q, want %q", cfg.BindAddress, "0.0.0.0")
	}
	if cfg.ProxyPort != 18080 {
		t.Errorf("ProxyPort = %d, want %d", cfg.ProxyPort, 18080)
	}
	if !g.closed {
		t.Errorf("applyPolicy did not Close the getter")
	}
}

func TestApplyPolicy_EmptyAddressIgnored(t *testing.T) {
	cfg := defaults()
	cfg.BindAddress = "127.0.0.1"
	g := &fakeRegistry{strings: map[string]string{"Address": ""}}
	applyPolicy(cfg, g)
	if cfg.BindAddress != "127.0.0.1" {
		t.Errorf("empty Address overrode BindAddress to %q", cfg.BindAddress)
	}
}

func TestApplyPolicy_OutOfRangePortIgnored(t *testing.T) {
	cases := []uint64{0, 65536, 1 << 30}
	for _, port := range cases {
		cfg := defaults()
		cfg.ProxyPort = 8080
		g := &fakeRegistry{ints: map[string]uint64{"Port": port}}
		applyPolicy(cfg, g)
		if cfg.ProxyPort != 8080 {
			t.Errorf("out-of-range port %d overrode ProxyPort to %d", port, cfg.ProxyPort)
		}
	}
}

func TestApplyPolicy_AbsentKeysLeaveDefaults(t *testing.T) {
	cfg := defaults()
	cfg.BindAddress = "127.0.0.1"
	cfg.ProxyPort = 8080
	applyPolicy(cfg, &fakeRegistry{})
	if cfg.BindAddress != "127.0.0.1" || cfg.ProxyPort != 8080 {
		t.Errorf("absent keys mutated cfg: bind %q port %d", cfg.BindAddress, cfg.ProxyPort)
	}
}
