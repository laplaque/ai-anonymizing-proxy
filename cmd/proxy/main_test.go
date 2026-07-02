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

// maxBindAttempts bounds how many times a test re-launches the proxy after
// losing the freePort/freeAddr TOCTOU race (issue #140): the helpers hand out
// a port number, not a reservation, so another process can bind the port
// before the consumer does. Each retry allocates fresh ports, so consecutive
// losses are independent and five attempts make a spurious failure
// vanishingly unlikely even under heavy ephemeral-port contention.
const maxBindAttempts = 5

// bindConflict is the kernel's EADDRINUSE text. It appears in the proxy's
// log exactly when a listener lost the re-bind race for its port.
const bindConflict = "bind: address already in use"

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
//
// The subprocess re-binds ports handed out by freePort, so it can lose the
// TOCTOU race (issue #140) at any point before shutdown — log.Fatalf then
// exits it with an EADDRINUSE message. That is a lost coin toss, not a
// regression: the test relaunches on fresh ports instead of flaking.
func TestMain_HelperProcess_Lifecycle(t *testing.T) {
	for attempt := 1; ; attempt++ {
		if lifecycleAttempt(t) {
			return
		}
		if attempt == maxBindAttempts {
			t.Fatalf("helper lost the freePort bind race %d times in a row", attempt)
		}
		t.Logf("attempt %d/%d: helper lost the freePort bind race, relaunching on fresh ports", attempt, maxBindAttempts)
	}
}

// lifecycleAttempt runs one full start → ready → SIGTERM → clean-exit cycle
// against a freshly launched helper subprocess. It returns false only when
// the subprocess died because a freePort-allocated port was stolen before it
// could bind (EADDRINUSE in its log), so the caller can relaunch; every
// other failure fails the test in place.
func lifecycleAttempt(t *testing.T) bool {
	t.Helper()

	cmd := helperCmd(t)
	cmd.Env = append(cmd.Env,
		"BIND_ADDRESS=127.0.0.1",
		fmt.Sprintf("PROXY_PORT=%d", freePort(t)),
		fmt.Sprintf("MANAGEMENT_PORT=%d", freePort(t)),
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
	// Reap in a goroutine so exit is observable while polling the log. Once
	// done receives, cmd.Wait has returned, which also guarantees stderr
	// holds everything the subprocess wrote.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() }) // no-op once reaped

	lostRace := func() bool { return strings.Contains(stderr.String(), bindConflict) }

	// Startup: wait for the readiness line, watching for an early exit so a
	// lost bind race is detected immediately instead of eating the timeout.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), "[PROXY] Listening on") {
		if time.Now().After(deadline) {
			t.Fatalf("did not see %q in log within 10s\n%s", "[PROXY] Listening on", stderr.String())
		}
		select {
		case <-done:
			if lostRace() {
				return false
			}
			t.Fatalf("helper exited before readiness:\n%s", stderr.String())
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Shutdown. The management listener binds concurrently with proxy
	// readiness, so a stolen management port can still kill the subprocess
	// anywhere in this phase — those paths return false like the ones above.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		if lostRace() {
			return false
		}
		t.Fatalf("signal: %v\n%s", err, stderr.String())
	}
	select {
	case err := <-done:
		if err == nil {
			return true
		}
		if lostRace() {
			return false
		}
		t.Errorf("process exited with error: %v\n%s", err, stderr.String())
		return true
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("process did not exit within 10s of SIGTERM\n%s", stderr.String())
		return false // unreachable: Fatalf panics
	}
}

// TestMain_HelperProcess_ProxyPortConflict_Fatal pre-binds the proxy port so
// the subprocess's srv.ListenAndServe() fails, exercising runHTTPServer's
// log.Fatalf branch.
func TestMain_HelperProcess_ProxyPortConflict_Fatal(t *testing.T) {
	testHelperPortConflict(t, "PROXY_PORT", "MANAGEMENT_PORT", "[PROXY] Fatal", "[MANAGEMENT] Fatal")
}

// TestMain_HelperProcess_MgmtPortConflict_Fatal pre-binds the management port
// so the subprocess's mgmt.ListenAndServe() fails, exercising runManagementAPI's
// log.Fatalf branch.
func TestMain_HelperProcess_MgmtPortConflict_Fatal(t *testing.T) {
	testHelperPortConflict(t, "MANAGEMENT_PORT", "PROXY_PORT", "[MANAGEMENT] Fatal", "[PROXY] Fatal")
}

// testHelperPortConflict launches the helper with the pinnedVar port held by
// a live listener in this process, so the subprocess must die with wantTag.
// The other port (freeVar) comes from freePort and can be stolen before the
// subprocess binds it (issue #140); when the subprocess instead dies with
// otherTag plus EADDRINUSE, that's the lost race — relaunch with a fresh
// port rather than flake.
func testHelperPortConflict(t *testing.T, pinnedVar, freeVar, wantTag, otherTag string) {
	t.Helper()
	ln := listenLocal(t)
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T is not *net.TCPAddr", ln.Addr())
	}

	for attempt := 1; ; attempt++ {
		cmd := helperCmd(t)
		cmd.Env = append(cmd.Env,
			"BIND_ADDRESS=127.0.0.1",
			fmt.Sprintf("%s=%d", pinnedVar, addr.Port),
			fmt.Sprintf("%s=%d", freeVar, freePort(t)),
			"ENABLED_PACKS=SECRETS,GLOBAL",
			"USE_AI_DETECTION=false",
		)
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-zero exit on %s conflict, got success\n%s", pinnedVar, out)
		}
		if strings.Contains(string(out), wantTag) {
			return
		}
		if strings.Contains(string(out), otherTag) && strings.Contains(string(out), bindConflict) && attempt < maxBindAttempts {
			t.Logf("attempt %d/%d: %s stolen (lost freePort race), relaunching", attempt, maxBindAttempts, freeVar)
			continue
		}
		t.Errorf("expected %q in output, got:\n%s", wantTag, out)
		return
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

// TestMain_HelperProcess_EnvFile_Loaded re-execs the binary with --env-file
// pointing at a temp file that supplies ENABLED_PACKS, then exits via
// --generate-ca. Asserts the success branch of main()'s envfile.Apply call.
func TestMain_HelperProcess_EnvFile_Loaded(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")
	if err := os.WriteFile(envPath, []byte("ENABLED_PACKS=SECRETS\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca.key")

	cmd := helperCmd(t, "--env-file", envPath, "--generate-ca", "--ca-cert", cert, "--ca-key", key)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("env-file + generate-ca: %v\n%s", err, out)
	}
}

// TestMain_HelperProcess_EnvFile_Fatal re-execs with --env-file pointing at
// a missing path so envfile.Apply returns an error and main()'s [ENV]
// log.Fatalf fires.
func TestMain_HelperProcess_EnvFile_Fatal(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.env")

	cmd := helperCmd(t, "--env-file", missing)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on missing env file, got success\n%s", out)
	}
	if !strings.Contains(string(out), "[ENV]") {
		t.Errorf("expected '[ENV]' in output, got:\n%s", out)
	}
}

// TestMain_HelperProcess_RemoveCAFromStore_Fatal re-execs with
// --remove-ca-from-store. On non-Windows the helper returns a clear
// error; on Windows it requires a real cert path and elevated context,
// so the helper test only asserts the dispatch path (main's [CA]
// log.Fatalf) under both platforms.
func TestMain_HelperProcess_RemoveCAFromStore_Fatal(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-cert.pem")

	cmd := helperCmd(t, "--remove-ca-from-store", "--ca-cert", missing)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on missing cert, got success\n%s", out)
	}
	if !strings.Contains(string(out), "[CA]") {
		t.Errorf("expected '[CA]' in output, got:\n%s", out)
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
