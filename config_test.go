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

func TestLoadFile_ValidJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "config-*.json")
	if err != nil {
		t.Fatal(err)
	}

	data, marshalErr := json.Marshal(map[string]any{
		"proxyPort":      9999,
		"ollamaModel":    "mistral:7b",
		"useAIDetection": false,
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := defaults()
	loadFile(cfg, f.Name())

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

func TestLoadFile_Missing_IsNoOp(t *testing.T) {
	cfg := defaults()
	loadFile(cfg, "/nonexistent/path/config.json")
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort changed unexpectedly: %d", cfg.ProxyPort)
	}
}

func TestLoadFile_InvalidJSON_PreservesDefaults(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "config-bad-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{this is not json}"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := defaults()
	loadFile(cfg, f.Name())
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort changed on bad JSON: %d", cfg.ProxyPort)
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

func TestDefaults_PackConfig(t *testing.T) {
	cfg := defaults()
	if cfg.PackDecayRate != 0.05 {
		t.Errorf("PackDecayRate: got %f, want 0.05", cfg.PackDecayRate)
	}
	if len(cfg.PatternPacks) != 8 {
		t.Errorf("PatternPacks: got %d entries, want 8", len(cfg.PatternPacks))
	}
	enabledCount := 0
	for _, pp := range cfg.PatternPacks {
		if pp.Enabled {
			enabledCount++
		}
	}
	if enabledCount != 3 {
		t.Errorf("enabled packs: got %d, want 3 (GLOBAL, DE, SECRETS)", enabledCount)
	}
}

func TestValidatePacks_DecayRateOutOfRange(t *testing.T) {
	cfg := defaults()
	cfg.PackDecayRate = -1.0
	cfg.validatePacks()
	if cfg.PackDecayRate != 0.05 {
		t.Errorf("PackDecayRate should clamp to 0.05 when negative, got %f", cfg.PackDecayRate)
	}

	cfg.PackDecayRate = 2.0
	cfg.validatePacks()
	if cfg.PackDecayRate != 0.05 {
		t.Errorf("PackDecayRate should clamp to 0.05 when >1.0, got %f", cfg.PackDecayRate)
	}
}

func TestValidateCustomPatterns_ProtectedType(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "test", Type: "EMAIL", Confidence: 0.9},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 0 {
		t.Errorf("protected type EMAIL should be skipped, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_InvalidRegex(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "[invalid", Type: "CUSTOM", Confidence: 0.9},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 0 {
		t.Errorf("invalid regex should be skipped, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_EmptyPack(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "", Pattern: "test", Type: "CUSTOM", Confidence: 0.9},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 0 {
		t.Errorf("empty pack should be skipped, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_ConfidenceOutOfRange(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "test", Type: "CUSTOM", Confidence: 1.5},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 0 {
		t.Errorf("confidence >1.0 should be skipped, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_TypeTooLong(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "test", Type: "TOOLONGTYPENAME1", Confidence: 0.9},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 0 {
		t.Errorf("type >15 chars should be skipped, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_EmptyType(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "test", Type: "", Confidence: 0.9},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 0 {
		t.Errorf("empty type should be skipped, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_ValidEntry(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "test-pattern", Type: "CUSTOM", Confidence: 0.9},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 1 {
		t.Errorf("valid entry should be kept, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestValidateCustomPatterns_LiteralSkipsRegexValidation(t *testing.T) {
	cfg := defaults()
	cfg.CustomPIIPatterns = []CustomPIIPattern{
		{Pack: "GLOBAL", Pattern: "[invalid regex but literal", Type: "CUSTOM", Confidence: 0.9, Literal: true},
	}
	cfg.validateCustomPatterns()
	if len(cfg.CustomPIIPatterns) != 1 {
		t.Errorf("literal entry should skip regex validation, got %d entries", len(cfg.CustomPIIPatterns))
	}
}

func TestResolvePIIInstruction(t *testing.T) {
	cfg := defaults()

	instr := cfg.ResolvePIIInstruction("claude-sonnet-4-6")
	if instr == "" {
		t.Error("expected non-empty instruction for claude model")
	}

	instr = cfg.ResolvePIIInstruction("gpt-4")
	if instr == "" {
		t.Error("expected non-empty instruction for gpt model")
	}

	instr = cfg.ResolvePIIInstruction("unknown-model")
	if instr == "" {
		t.Error("expected default instruction for unknown model")
	}
}
