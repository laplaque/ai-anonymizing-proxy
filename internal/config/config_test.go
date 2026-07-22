package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := defaults()

	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort: got %d, want 8080", cfg.ProxyPort)
	}
	if cfg.ManagementPort != 8081 {
		t.Errorf("ManagementPort: got %d, want 8081", cfg.ManagementPort)
	}
	if cfg.OllamaEndpoint != "http://localhost:11434" {
		t.Errorf("OllamaEndpoint: got %s", cfg.OllamaEndpoint)
	}
	if cfg.OllamaModel != "qwen2.5:3b" {
		t.Errorf("OllamaModel: got %s", cfg.OllamaModel)
	}
	if !cfg.UseAIDetection {
		t.Error("UseAIDetection should default to true")
	}
	if cfg.AIConfidence != 0.7 {
		t.Errorf("AIConfidence: got %f, want 0.7", cfg.AIConfidence)
	}
	if cfg.OllamaMaxConcurrent != 1 {
		t.Errorf("OllamaMaxConcurrent: got %d, want 1", cfg.OllamaMaxConcurrent)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel: got %s", cfg.LogLevel)
	}
	if cfg.CACertFile != "ca-cert.pem" {
		t.Errorf("CACertFile: got %s", cfg.CACertFile)
	}
	if cfg.CAKeyFile != "ca-key.pem" {
		t.Errorf("CAKeyFile: got %s", cfg.CAKeyFile)
	}
	if cfg.BindAddress != "127.0.0.1" {
		t.Errorf("BindAddress: got %s", cfg.BindAddress)
	}
	if len(cfg.AIAPIDomains) == 0 {
		t.Error("AIAPIDomains should not be empty")
	}
	if len(cfg.AuthDomains) == 0 {
		t.Error("AuthDomains should not be empty")
	}
	if len(cfg.AuthPaths) == 0 {
		t.Error("AuthPaths should not be empty")
	}
}

func TestLoadEnv_ProxyPort(t *testing.T) {
	t.Setenv("PROXY_PORT", "9090")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.ProxyPort != 9090 {
		t.Errorf("ProxyPort: got %d, want 9090", cfg.ProxyPort)
	}
}

func TestLoadEnv_ManagementPort(t *testing.T) {
	t.Setenv("MANAGEMENT_PORT", "9091")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.ManagementPort != 9091 {
		t.Errorf("ManagementPort: got %d, want 9091", cfg.ManagementPort)
	}
}

func TestLoadEnv_OllamaEndpoint(t *testing.T) {
	t.Setenv("OLLAMA_ENDPOINT", "http://remote:11434")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.OllamaEndpoint != "http://remote:11434" {
		t.Errorf("OllamaEndpoint: got %s", cfg.OllamaEndpoint)
	}
}

func TestLoadEnv_OllamaModel(t *testing.T) {
	t.Setenv("OLLAMA_MODEL", "llama3:8b")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.OllamaModel != "llama3:8b" {
		t.Errorf("OllamaModel: got %s", cfg.OllamaModel)
	}
}

func TestLoadEnv_DisableAIDetection(t *testing.T) {
	t.Setenv("USE_AI_DETECTION", "false")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.UseAIDetection {
		t.Error("UseAIDetection should be false")
	}
}

func TestLoadEnv_AIConfidence(t *testing.T) {
	t.Setenv("AI_CONFIDENCE_THRESHOLD", "0.9")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.AIConfidence != 0.9 {
		t.Errorf("AIConfidence: got %f, want 0.9", cfg.AIConfidence)
	}
}

func TestLoadEnv_OllamaMaxConcurrent(t *testing.T) {
	t.Setenv("OLLAMA_MAX_CONCURRENT", "4")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.OllamaMaxConcurrent != 4 {
		t.Errorf("OllamaMaxConcurrent: got %d, want 4", cfg.OllamaMaxConcurrent)
	}
}

func TestLoadEnv_OllamaMaxConcurrent_Zero_Ignored(t *testing.T) {
	t.Setenv("OLLAMA_MAX_CONCURRENT", "0")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.OllamaMaxConcurrent != 1 {
		t.Errorf("OllamaMaxConcurrent: got %d, want 1 (zero should be ignored)", cfg.OllamaMaxConcurrent)
	}
}

func TestLoadEnv_LogLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "debug")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: got %s", cfg.LogLevel)
	}
}

func TestLoadEnv_CACertFile(t *testing.T) {
	t.Setenv("CA_CERT_FILE", "/etc/ssl/my-ca.crt")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.CACertFile != "/etc/ssl/my-ca.crt" {
		t.Errorf("CACertFile: got %s", cfg.CACertFile)
	}
}

func TestLoadEnv_CAKeyFile(t *testing.T) {
	t.Setenv("CA_KEY_FILE", "/etc/ssl/my-ca.key")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.CAKeyFile != "/etc/ssl/my-ca.key" {
		t.Errorf("CAKeyFile: got %s", cfg.CAKeyFile)
	}
}

func TestLoadEnv_BindAddress(t *testing.T) {
	t.Setenv("BIND_ADDRESS", "0.0.0.0")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.BindAddress != "0.0.0.0" {
		t.Errorf("BindAddress: got %s", cfg.BindAddress)
	}
}

func TestLoadEnv_ManagementToken(t *testing.T) {
	t.Setenv("MANAGEMENT_TOKEN", "secret-token")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.ManagementToken != "secret-token" {
		t.Errorf("ManagementToken: got %s", cfg.ManagementToken)
	}
}

func TestLoadEnv_InvalidPort_Ignored(t *testing.T) {
	t.Setenv("PROXY_PORT", "not-a-number")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort: got %d, want 8080 (invalid env should be ignored)", cfg.ProxyPort)
	}
}

func TestMergeJSON_ValidJSON(t *testing.T) {
	data, marshalErr := json.Marshal(map[string]any{
		"proxyPort":      9999,
		"ollamaModel":    "mistral:7b",
		"useAIDetection": false,
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}

	cfg := defaults()
	mergeJSON(cfg, configFileName, data)

	if cfg.ProxyPort != 9999 {
		t.Errorf("ProxyPort: got %d, want 9999", cfg.ProxyPort)
	}
	if cfg.OllamaModel != "mistral:7b" {
		t.Errorf("OllamaModel: got %s", cfg.OllamaModel)
	}
	if cfg.UseAIDetection {
		t.Error("UseAIDetection should be false after file load")
	}
}

func TestLoadFile_ReadsConfigFromWorkingDir(t *testing.T) {
	t.Chdir(t.TempDir())
	data, err := json.Marshal(map[string]any{"proxyPort": 9999})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFileName, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := defaults()
	loadFile(cfg)
	if cfg.ProxyPort != 9999 {
		t.Errorf("ProxyPort: got %d, want 9999 (file in cwd should load)", cfg.ProxyPort)
	}
}

func TestLoadFile_Missing_IsNoOp(t *testing.T) {
	t.Chdir(t.TempDir()) // empty dir: no proxy-config.json present
	cfg := defaults()
	loadFile(cfg)
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort changed unexpectedly: %d", cfg.ProxyPort)
	}
}

func TestMergeJSON_InvalidJSON_PreservesDefaults(t *testing.T) {
	cfg := defaults()
	mergeJSON(cfg, configFileName, []byte("{this is not json}"))
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort changed on bad JSON: %d", cfg.ProxyPort)
	}
}

// TestMergeJSON_TypeError_LeavesConfigUntouched pins the contract that a
// document failing mid-decode applies NOTHING. encoding/json sets fields
// that precede a type error, so a naive Unmarshal(data, cfg) would leave
// enabledPacks (the issue #70 ordering invariant) mutated while returning
// an error — silently degrading PII stripping behind a "could not parse"
// warning. mergeJSON must decode into a scratch copy and merge only on
// full success.
func TestMergeJSON_TypeError_LeavesConfigUntouched(t *testing.T) {
	cfg := defaults()
	wantPacks := append([]string(nil), cfg.EnabledPacks...)
	wantModel := cfg.OllamaModel

	// enabledPacks (valid) precedes proxyPort (type error) in the document,
	// so a partial apply would take the reordered pack list before failing.
	mergeJSON(cfg, configFileName, []byte(`{"enabledPacks":["GLOBAL"],"ollamaModel":"evil","proxyPort":"not-a-number"}`))

	if got := cfg.EnabledPacks; len(got) != len(wantPacks) {
		t.Errorf("EnabledPacks partially applied on type error: got %v, want %v", got, wantPacks)
	}
	if cfg.OllamaModel != wantModel {
		t.Errorf("OllamaModel partially applied on type error: got %q, want %q", cfg.OllamaModel, wantModel)
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort changed on type error: %d", cfg.ProxyPort)
	}
}

func TestDefaults_EnabledPacks(t *testing.T) {
	cfg := defaults()
	wantOrder := []string{"SECRETS", "GLOBAL", "DE"}
	if len(cfg.EnabledPacks) != len(wantOrder) {
		t.Fatalf("EnabledPacks length: got %d, want %d", len(cfg.EnabledPacks), len(wantOrder))
	}
	for i, p := range cfg.EnabledPacks {
		if p != wantOrder[i] {
			t.Errorf("EnabledPacks[%d]: got %q, want %q", i, p, wantOrder[i])
		}
	}
}

func TestDefaults_PackDecayRate(t *testing.T) {
	cfg := defaults()
	if cfg.PackDecayRate != 0.05 {
		t.Errorf("PackDecayRate: got %f, want 0.05", cfg.PackDecayRate)
	}
}

func TestLoadEnv_EnabledPacks(t *testing.T) {
	t.Setenv("ENABLED_PACKS", "GLOBAL,US,SECRETS")
	cfg := defaults()
	loadEnv(cfg)
	if len(cfg.EnabledPacks) != 3 {
		t.Fatalf("EnabledPacks length: got %d, want 3", len(cfg.EnabledPacks))
	}
	if cfg.EnabledPacks[0] != "GLOBAL" || cfg.EnabledPacks[1] != "US" || cfg.EnabledPacks[2] != "SECRETS" {
		t.Errorf("EnabledPacks: got %v", cfg.EnabledPacks)
	}
}

func TestLoadEnv_PackDecayRate(t *testing.T) {
	t.Setenv("PACK_DECAY_RATE", "0.10")
	cfg := defaults()
	loadEnv(cfg)
	if cfg.PackDecayRate != 0.10 {
		t.Errorf("PackDecayRate: got %f, want 0.10", cfg.PackDecayRate)
	}
}

func TestLoad_PackDecayRateClampNegative(t *testing.T) {
	t.Setenv("PACK_DECAY_RATE", "-0.5")
	cfg := Load()
	if cfg.PackDecayRate != 0 {
		t.Errorf("negative decay rate should clamp to 0, got %f", cfg.PackDecayRate)
	}
}

func TestLoad_PackDecayRateClampAboveOne(t *testing.T) {
	t.Setenv("PACK_DECAY_RATE", "2.0")
	cfg := Load()
	if cfg.PackDecayRate != 1.0 {
		t.Errorf("decay rate > 1 should clamp to 1.0, got %f", cfg.PackDecayRate)
	}
}

func TestResolvePIIInstruction_PrefixMatch(t *testing.T) {
	cfg := defaults()
	instruction := cfg.ResolvePIIInstruction("claude-sonnet-4-6")
	if instruction == "" {
		t.Error("expected non-empty instruction for claude prefix")
	}
	if instruction == cfg.PIIInstructions["default"] {
		t.Error("expected claude-specific instruction, got default")
	}
}

func TestResolvePIIInstruction_FallbackToDefault(t *testing.T) {
	cfg := defaults()
	instruction := cfg.ResolvePIIInstruction("unknown-model")
	if instruction != cfg.PIIInstructions["default"] {
		t.Error("expected default instruction for unknown model")
	}
}

func TestResolvePIIInstruction_EmptyModel(t *testing.T) {
	cfg := defaults()
	instruction := cfg.ResolvePIIInstruction("")
	if instruction != cfg.PIIInstructions["default"] {
		t.Error("expected default instruction for empty model")
	}
}

func TestResolvePIIInstruction_NoDefault(t *testing.T) {
	cfg := defaults()
	cfg.PIIInstructions = map[string]string{"claude": "test"}
	instruction := cfg.ResolvePIIInstruction("gpt-4")
	if instruction != "" {
		t.Errorf("expected empty instruction when no default key, got %q", instruction)
	}
}

// TestDefaultConfigNewDomains verifies that the Phase 1 aggregator and
// provider domains all appear in the default AIAPIDomains slice, and that
// the new oauth2.googleapis.com entry appears in AuthDomains.
func TestDefaultConfigNewDomains(t *testing.T) {
	cfg := defaults()
	requiredAPI := []string{
		"api.groq.com", "api.deepseek.com", "api.fireworks.ai",
		"api.x.ai", "api.endpoints.anyscale.com",
		"openrouter.ai", "api.portkey.ai",
	}
	apiSet := make(map[string]bool, len(cfg.AIAPIDomains))
	for _, d := range cfg.AIAPIDomains {
		apiSet[d] = true
	}
	for _, d := range requiredAPI {
		if !apiSet[d] {
			t.Errorf("missing default AI API domain: %s", d)
		}
	}

	requiredAuth := []string{"oauth2.googleapis.com"}
	authSet := make(map[string]bool, len(cfg.AuthDomains))
	for _, d := range cfg.AuthDomains {
		authSet[d] = true
	}
	for _, d := range requiredAuth {
		if !authSet[d] {
			t.Errorf("missing default auth domain: %s", d)
		}
	}
}

// TestDefaultConfigGlobDomains pins the Phase-3 segment-glob defaults
// into the test suite. A future refactor that drops or renames any of
// these entries will fail this test instead of silently degrading the
// security-classifier surface.
func TestDefaultConfigGlobDomains(t *testing.T) {
	cfg := defaults()
	required := []string{
		"*.openai.azure.com",          // Azure OpenAI
		"aiplatform.googleapis.com",   // Vertex AI global
		"*-aiplatform.googleapis.com", // Vertex AI regional (hyphen-prefix)
		"*.aiplatform.googleapis.com", // Vertex AI defensive 4-label form
		"bedrock-runtime.*.amazonaws.com",
		"bedrock-agent-runtime.*.amazonaws.com",
	}
	apiSet := make(map[string]bool, len(cfg.AIAPIDomains))
	for _, d := range cfg.AIAPIDomains {
		apiSet[d] = true
	}
	for _, d := range required {
		if !apiSet[d] {
			t.Errorf("missing Phase-3 default AI API domain: %s", d)
		}
	}
}

// TestCopilotDomainRegistered verifies the GitHub Copilot domain appears in
// the default AIAPIDomains slice.
func TestCopilotDomainRegistered(t *testing.T) {
	cfg := defaults()
	found := false
	for _, d := range cfg.AIAPIDomains {
		if d == "api.githubcopilot.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("api.githubcopilot.com not in default AIAPIDomains")
	}
}

// TestCloudflareGatewayDomainRegistered verifies the Cloudflare AI Gateway
// domain appears in the default AIAPIDomains slice.
func TestCloudflareGatewayDomainRegistered(t *testing.T) {
	cfg := defaults()
	found := false
	for _, d := range cfg.AIAPIDomains {
		if d == "gateway.ai.cloudflare.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("gateway.ai.cloudflare.com not in default AIAPIDomains")
	}
}

// TestGitHubAuthDomainRegistered verifies github.com appears in the default
// AuthDomains slice so Copilot's device-auth flow bypasses anonymization.
func TestGitHubAuthDomainRegistered(t *testing.T) {
	cfg := defaults()
	found := false
	for _, d := range cfg.AuthDomains {
		if d == "github.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("github.com not in default AuthDomains")
	}
}

func TestLoad_ReturnsNonNil(t *testing.T) {
	cfg := Load()
	if cfg == nil {
		t.Fatal("Load() returned nil")
	}
	if cfg.ProxyPort <= 0 {
		t.Errorf("ProxyPort should be positive, got %d", cfg.ProxyPort)
	}
}
