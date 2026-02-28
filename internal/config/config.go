// Package config loads and holds all proxy configuration.
// Settings are layered: defaults → proxy-config.json → environment variables (env vars win).
// Upstream proxy chaining is configured via the UpstreamProxy field / UPSTREAM_PROXY env var.
package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
)

// Config holds the full proxy configuration.
type Config struct {
	ProxyPort           int     `json:"proxyPort"`
	ManagementPort      int     `json:"managementPort"`
	OllamaEndpoint      string  `json:"ollamaEndpoint"`
	OllamaModel         string  `json:"ollamaModel"`
	UseAIDetection      bool    `json:"useAIDetection"`
	AIConfidence        float64 `json:"aiConfidenceThreshold"`
	OllamaMaxConcurrent int     `json:"ollamaMaxConcurrent"`
	LogLevel            string  `json:"logLevel"`

	CACertFile      string `json:"caCertFile"`
	CAKeyFile       string `json:"caKeyFile"`
	BindAddress     string `json:"bindAddress"`
	ManagementToken string `json:"managementToken"`
	UpstreamProxy   string `json:"upstreamProxy"`
	OllamaCacheFile string `json:"ollamaCacheFile"` // path to bbolt persistent cache; empty = in-memory only

	AIAPIDomains []string `json:"aiApiDomains"`
	AuthDomains  []string `json:"authDomains"`
	AuthPaths    []string `json:"authPaths"`

	// PIIInstructions maps LLM family prefix (e.g. "claude", "gpt") to the
	// system instruction injected when PII tokens are present in a request.
	// Lookup is prefix-based: "claude-sonnet-4-6" matches key "claude".
	// The special key "default" is used when no prefix matches.
	PIIInstructions map[string]string `json:"piiInstructions"`
}

// Load returns config with defaults overridden by proxy-config.json and env vars.
func Load() *Config {
	cfg := defaults()
	loadFile(cfg, "proxy-config.json")
	loadEnv(cfg)
	return cfg
}

func defaults() *Config {
	return &Config{
		ProxyPort:           8080,
		ManagementPort:      8081,
		OllamaEndpoint:      "http://localhost:11434",
		OllamaModel:         "qwen2.5:3b",
		UseAIDetection:      true,
		AIConfidence:        0.7,
		OllamaMaxConcurrent: 1,
		LogLevel:            "info",
		CACertFile:          "ca-cert.pem",
		CAKeyFile:           "ca-key.pem",
		BindAddress:         "127.0.0.1",
		OllamaCacheFile:     "ollama-cache.db",
		AIAPIDomains: []string{
			"api.anthropic.com",
			"api.openai.com",
			"api.cohere.ai",
			"generativelanguage.googleapis.com",
			"api.mistral.ai",
			"api.together.xyz",
			"api.perplexity.ai",
			"api.replicate.com",
			"api.huggingface.co",
		},
		AuthDomains: []string{
			"accounts.google.com",
			"login.microsoftonline.com",
			"auth0.com",
			"okta.com",
		},
		AuthPaths: []string{
			"/auth", "/login", "/signin", "/signup", "/register",
			"/token", "/oauth", "/authenticate", "/session",
			"/v1/auth", "/api/auth", "/api/login", "/api/token",
		},
		PIIInstructions: map[string]string{
			"claude": "PRIVACY TOKENS: This request contains privacy-preserving placeholders" +
				" matching the pattern [PII_XXXXXXXX] (8 hex characters). You MUST reproduce" +
				" every such token EXACTLY as written in your response. Do NOT replace them with" +
				" example values, email addresses, phone numbers, names, or any other substitutes." +
				" Treat [PII_*] tokens as opaque identifiers that must pass through unchanged.",
			"gpt": "PRIVACY TOKENS: This request contains privacy-preserving placeholders" +
				" matching the pattern [PII_XXXXXXXX] (8 hex characters). Reproduce every such" +
				" token verbatim in your response. Do not substitute them with example values.",
			"default": "PRIVACY TOKENS: This request contains privacy-preserving placeholders" +
				" matching the pattern [PII_XXXXXXXX] (8 hex characters). Reproduce every such" +
				" token verbatim in your response. Do not substitute them with example values.",
		},
	}
}

// ResolvePIIInstruction returns the PII system instruction for the given model
// string using prefix matching. "claude-sonnet-4-6" matches key "claude".
// Falls back to the "default" key, then to an empty string if neither exists.
func (c *Config) ResolvePIIInstruction(model string) string {
	for key, instruction := range c.PIIInstructions {
		if key == "default" {
			continue
		}
		if len(model) >= len(key) && model[:len(key)] == key {
			return instruction
		}
	}
	if fallback, ok := c.PIIInstructions["default"]; ok {
		return fallback
	}
	return ""
}

func loadFile(cfg *Config, path string) {
	data, err := os.ReadFile(path) //nolint:gosec // G703: path is a controlled config file path, not user input
	if err != nil {
		return // file is optional
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("[CONFIG] Warning: could not parse %s: %v", path, err)
	} else {
		log.Printf("[CONFIG] Loaded %s", path)
	}
}

func loadEnv(cfg *Config) {
	if v := os.Getenv("PROXY_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ProxyPort = n
		}
	}
	if v := os.Getenv("MANAGEMENT_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ManagementPort = n
		}
	}
	if v := os.Getenv("OLLAMA_ENDPOINT"); v != "" {
		cfg.OllamaEndpoint = v
	}
	if v := os.Getenv("OLLAMA_MODEL"); v != "" {
		cfg.OllamaModel = v
	}
	if v := os.Getenv("USE_AI_DETECTION"); v == "false" {
		cfg.UseAIDetection = false
	}
	if v := os.Getenv("AI_CONFIDENCE_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.AIConfidence = f
		}
	}
	if v := os.Getenv("OLLAMA_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.OllamaMaxConcurrent = n
		}
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("CA_CERT_FILE"); v != "" {
		cfg.CACertFile = v
	}
	if v := os.Getenv("CA_KEY_FILE"); v != "" {
		cfg.CAKeyFile = v
	}
	if v := os.Getenv("BIND_ADDRESS"); v != "" {
		cfg.BindAddress = v
	}
	if v := os.Getenv("MANAGEMENT_TOKEN"); v != "" {
		cfg.ManagementToken = v
	}
	if v := os.Getenv("UPSTREAM_PROXY"); v != "" {
		cfg.UpstreamProxy = v
	}
	if v := os.Getenv("OLLAMA_CACHE_FILE"); v != "" {
		cfg.OllamaCacheFile = v
	}
}
