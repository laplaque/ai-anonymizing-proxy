package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ai-anonymizing-proxy/internal/config"
)

// TestMain dispatches to main() when GO_WANT_HELPER_PROCESS=1, allowing
// helper-process tests to re-exec this test binary as the production binary.
// Pattern copied from stdlib os/exec internal tests.
func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// helperCmd builds an *exec.Cmd that re-execs this test binary as the
// production proxy. Centralizing the os.Args[0] call site means there's
// exactly one gosec G204 suppression in the file (here) instead of one per
// test — and the suppression sits next to the explanation of why the
// pattern is safe (the target is the test binary itself, not external
// input). Callers append cmd.Env / cmd.Dir / cmd.Stdout / cmd.Stderr as
// they need them.
func helperCmd(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	//nolint:gosec // G204: os.Args[0] is the test binary itself (the helper-process pattern from stdlib os/exec internal tests); the args are test-controlled flags, not external input.
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	return cmd
}

// captureStdout redirects os.Stdout to a pipe for the duration of fn,
// then returns everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("pipe write close: %v", closeErr)
	}
	os.Stdout = old

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

func TestPrintBanner_ContainsExpectedFields(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:      8080,
		ManagementPort: 8081,
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "qwen2.5:3b",
		UseAIDetection: true,
	}

	out := captureStdout(t, func() { printBanner(cfg) })

	for _, want := range []string{"8080", "8081", "localhost:11434", "qwen2.5:3b"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in banner output, got:\n%s", want, out)
		}
	}
}

func TestPrintBanner_UpstreamProxy_FromEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://corporate:8888")

	cfg := &config.Config{ProxyPort: 8080, ManagementPort: 8081}
	out := captureStdout(t, func() { printBanner(cfg) })

	if !strings.Contains(out, "http://corporate:8888") {
		t.Errorf("expected upstream proxy in banner, got:\n%s", out)
	}
}

func TestPrintBanner_NoProxy_ShowsDirect(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")

	cfg := &config.Config{ProxyPort: 8080, ManagementPort: 8081}
	out := captureStdout(t, func() { printBanner(cfg) })

	if !strings.Contains(out, "direct") {
		t.Errorf("expected 'direct' in banner when no proxy set, got:\n%s", out)
	}
}

// TestPrintBanner_ZeroValueConfig_DoesNotPanic asserts that printBanner
// survives a zero-value *config.Config — a regression like a nil-map deref
// or missing-field panic on uninitialised input would be caught here.
// Inherited from the original TestMain_Smoke, kept as its own test so the
// guarantee survives the helper-process TestMain rewrite.
func TestPrintBanner_ZeroValueConfig_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printBanner panicked on zero-value config: %v", r)
		}
	}()
	_ = captureStdout(t, func() { printBanner(&config.Config{}) })
}

// TestRunGenerateCA exercises the cmd/proxy helper that --generate-ca
// dispatches to: it must reject empty path args, surface filesystem errors,
// and on success write both files with the right permission on the key.
// The cryptographic shape of the generated CA is covered by tests in
// internal/mitm — this test asserts only the contract cmd/proxy owns
// (path-arg validation + file-on-disk presence + key permission).
func TestRunGenerateCA(t *testing.T) {
	cases := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{name: "writes cert and key", cert: "ca.pem", key: "ca.key"},
		{name: "empty cert path", cert: "", key: "ca.key", wantErr: true},
		{name: "empty key path", cert: "ca.pem", key: "", wantErr: true},
		{name: "unwritable cert dir", cert: "missing/dir/ca.pem", key: "ca.key", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var certPath, keyPath string
			if tc.cert != "" {
				certPath = filepath.Join(dir, tc.cert)
			}
			if tc.key != "" {
				keyPath = filepath.Join(dir, tc.key)
			}

			err := runGenerateCA(certPath, keyPath)
			if (err != nil) != tc.wantErr {
				t.Fatalf("runGenerateCA err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			if _, statErr := os.Stat(certPath); statErr != nil {
				t.Errorf("cert not written: %v", statErr)
			}
			info, statErr := os.Stat(keyPath)
			if statErr != nil {
				t.Fatalf("stat key: %v", statErr)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("key perms = %o, want 0600", info.Mode().Perm())
			}
		})
	}
}

// TestMain_HelperProcess_Lifecycle re-execs this test binary as the proxy
// daemon, waits for it to bind its listener, sends SIGTERM, and verifies a
// clean exit. Exercises main()'s full startup-and-shutdown lifecycle.
func TestMain_HelperProcess_Lifecycle(t *testing.T) {
	proxyPort := freePort(t)
	mgmtPort := freePort(t)

	cmd := helperCmd(t)
	cmd.Env = append(cmd.Env,
		"BIND_ADDRESS=127.0.0.1",
		fmt.Sprintf("PROXY_PORT=%d", proxyPort),
		fmt.Sprintf("MANAGEMENT_PORT=%d", mgmtPort),
		"ENABLED_PACKS=SECRETS,GLOBAL",
		"USE_AI_DETECTION=false",
	)
	cmd.Dir = t.TempDir()
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	waitForLog(t, stderr, "[PROXY] Listening on", 10*time.Second)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("process exited with error: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("process did not exit within 10s of SIGTERM\n%s", stderr.String())
	}
}

// TestMain_HelperProcess_ProxyPortConflict_Fatal pre-binds the proxy port so
// the subprocess's srv.ListenAndServe() fails, exercising runHTTPServer's
// log.Fatalf branch.
func TestMain_HelperProcess_ProxyPortConflict_Fatal(t *testing.T) {
	ln := listenLocal(t)
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T is not *net.TCPAddr", ln.Addr())
	}
	proxyPort := addr.Port
	mgmtPort := freePort(t)

	cmd := helperCmd(t)
	cmd.Env = append(cmd.Env,
		"BIND_ADDRESS=127.0.0.1",
		fmt.Sprintf("PROXY_PORT=%d", proxyPort),
		fmt.Sprintf("MANAGEMENT_PORT=%d", mgmtPort),
		"ENABLED_PACKS=SECRETS,GLOBAL",
		"USE_AI_DETECTION=false",
	)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on proxy port conflict, got success\n%s", out)
	}
	if !strings.Contains(string(out), "[PROXY] Fatal") {
		t.Errorf("expected '[PROXY] Fatal' in output, got:\n%s", out)
	}
}

// TestMain_HelperProcess_MgmtPortConflict_Fatal pre-binds the management port
// so the subprocess's mgmt.ListenAndServe() fails, exercising runManagementAPI's
// log.Fatalf branch.
func TestMain_HelperProcess_MgmtPortConflict_Fatal(t *testing.T) {
	ln := listenLocal(t)
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T is not *net.TCPAddr", ln.Addr())
	}
	mgmtPort := addr.Port
	proxyPort := freePort(t)

	cmd := helperCmd(t)
	cmd.Env = append(cmd.Env,
		"BIND_ADDRESS=127.0.0.1",
		fmt.Sprintf("PROXY_PORT=%d", proxyPort),
		fmt.Sprintf("MANAGEMENT_PORT=%d", mgmtPort),
		"ENABLED_PACKS=SECRETS,GLOBAL",
		"USE_AI_DETECTION=false",
	)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on mgmt port conflict, got success\n%s", out)
	}
	if !strings.Contains(string(out), "[MANAGEMENT] Fatal") {
		t.Errorf("expected '[MANAGEMENT] Fatal' in output, got:\n%s", out)
	}
}

// TestMain_HelperProcess_ZeroPacks_Fatal verifies that a config with no packs
// enabled triggers the startup guard's log.Fatalf (non-zero exit). Covers that
// branch of main() which is otherwise unreachable from the lifecycle test.
func TestMain_HelperProcess_ZeroPacks_Fatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "proxy-config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"enabledPacks":[]}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := helperCmd(t)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on zero-packs guard, got success\n%s", out)
	}
	if !strings.Contains(string(out), "no PII detection packs enabled") {
		t.Errorf("expected guard message in output, got:\n%s", out)
	}
}

// TestMain_HelperProcess_GenerateCA re-execs this test binary with
// --generate-ca and asserts the cert+key pair are written to the given paths.
// Exercises main()'s flag-parsing dispatch and the success branch of the
// --generate-ca subcommand end-to-end.
func TestMain_HelperProcess_GenerateCA(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca.key")

	cmd := helperCmd(t, "--generate-ca", "--ca-cert", cert, "--ca-key", key)
	cmd.Dir = dir

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("--generate-ca: %v\n%s", err, out)
	}

	if _, err := os.Stat(cert); err != nil {
		t.Errorf("cert not written: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Errorf("key not written: %v", err)
	}
}

// TestMain_HelperProcess_GenerateCA_Fatal re-execs this test binary with
// --generate-ca and an empty --ca-cert path so runGenerateCA returns an
// error and main()'s [CA] log.Fatalf fires.
func TestMain_HelperProcess_GenerateCA_Fatal(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ca.key")

	cmd := helperCmd(t, "--generate-ca", "--ca-cert=", "--ca-key", key)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got success\n%s", out)
	}
	if !strings.Contains(string(out), "[CA]") {
		t.Errorf("expected '[CA]' in output, got:\n%s", out)
	}
}

// syncBuffer is a goroutine-safe wrapper around bytes.Buffer for use as
// cmd.Stderr while a poller in the parent reads it concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForLog(t *testing.T, buf *syncBuffer, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("did not see %q in log within %v\n%s", substr, timeout, buf.String())
}
