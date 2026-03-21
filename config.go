// Package config loads and holds all proxy configuration.
// Settings are layered: defaults → proxy-config.json → environment variables (env vars win).
// Upstream proxy chaining is configured via the UpstreamProxy field / UPSTREAM_PROXY env var.
package config

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// piiInstructionPrefix is the common prefix for all PII instruction strings.
const piiInstructionPrefix = "PRIVACY TOKENS: This request contains privacy-preserving placeholders" +
	" matching the pattern [PII_TYPE_XXXXXXXXXXXXXXXX] (16 hex characters). "

// PatternPack declares a named pattern pack and whether it is enabled.
type PatternPack struct {
	Pack    string `json:"pack"`
	Enabled bool   `json:"enabled"`
}

// CustomPIIPattern defines a user-supplied PII pattern scoped to a pack.
type CustomPIIPattern struct {
	Pack       string  `json:"pack"`
	Pattern    string  `json:"pattern"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Literal    bool    `json:"literal,omitempty"`
}

// piiInstructionDefault is the standard PII instruction used for models without a
// specialized instruction (gpt, default, and other non-Claude models).
const piiInstructionDefault = piiInstructionPrefix +
	"Reproduce every such token verbatim in your response. Do not substitute them with example values."

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

	// PackDecayRate is the per-position confidence decay for pattern packs.
	// Position 1 = multiplier 1.0. Each subsequent position reduces by this rate.
	// Must be in [0.0, 1.0]. Default: 0.05.
	PackDecayRate float64 `json:"packDecayRate"`

	// PatternPacks declares which pattern packs are available and their enable state.
	// Pack order determines precedence via the likelihood multiplier.
	PatternPacks []PatternPack `json:"patternPacks"`

	// CustomPIIPatterns are user-defined patterns scoped to a named pack.
	CustomPIIPatterns []CustomPIIPattern `json:"customPIIPatterns"`
}

// protectedPIITypes are built-in PII type names that custom patterns must not use.
var protectedPIITypes = map[string]bool{
	"EMAIL": true, "PHONE": true, "SSN": true, "CC": true,
	"IP": true, "APIKEY": true, "ADDRESS": true, "PERSON": true,
	"ORG": true, "LOCATION": true, "MISC": true,
}

// Load returns config with defaults overridden by proxy-config.json and env vars.
// It fatally exits if zero pattern packs are enabled.
func Load() *Config {
	cfg := defaults()
	loadFile(cfg, "proxy-config.json")
	loadEnv(cfg)
	cfg.validatePacks()
	return cfg
}

// validatePacks enforces startup guards on pattern pack configuration.
func (c *Config) validatePacks() {
	if c.PackDecayRate < 0.0 || c.PackDecayRate > 1.0 {
		log.Printf("[CONFIG] Warning: packDecayRate %.2f out of [0.0, 1.0], clamping to 0.05", c.PackDecayRate)
		c.PackDecayRate = 0.05
	}

	enabledCount := 0
	for _, pp := range c.PatternPacks {
		if pp.Enabled {
			enabledCount++
		}
	}
	if enabledCount == 0 {
		log.Fatalf("[CONFIG] Fatal: zero pattern packs enabled — proxy cannot start without at least one enabled pack")
	}

	c.validateCustomPatterns()
}

// validateCustomPatterns checks each custom PII pattern entry and logs warnings
// for invalid entries. Invalid entries are removed from the slice.
func (c *Config) validateCustomPatterns() {
	valid := make([]CustomPIIPattern, 0, len(c.CustomPIIPatterns))
	for _, cp := range c.CustomPIIPatterns {
		upper := strings.ToUpper(cp.Type)
		if upper == "" || len(upper) > 15 {
			log.Printf("[CONFIG] Warning: custom pattern type %q invalid (empty or >15 chars), skipping", cp.Type)
			continue
		}
		if protectedPIITypes[upper] {
			log.Printf("[CONFIG] Warning: custom pattern type %q conflicts with protected built-in type, skipping", cp.Type)
			continue
		}
		if cp.Confidence < 0.0 || cp.Confidence > 1.0 {
			log.Printf("[CONFIG] Warning: custom pattern %q confidence %.2f out of [0.0, 1.0], skipping", cp.Type, cp.Confidence)
			continue
		}
		if cp.Pack == "" {
			log.Printf("[CONFIG] Warning: custom pattern %q has no pack name, skipping", cp.Type)
			continue
		}
		if !cp.Literal {
			if _, err := regexp.Compile(cp.Pattern); err != nil {
				log.Printf("[CONFIG] Warning: custom pattern %q has invalid regex %q: %v, skipping", cp.Type, cp.Pattern, err)
				continue
			}
		}
		valid = append(valid, cp)
	}
	c.CustomPIIPatterns = valid
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
			"claude": piiInstructionPrefix +
				"You MUST reproduce every such token EXACTLY as written in your response. Do NOT replace them with" +
				" example values, email addresses, phone numbers, names, or any other substitutes." +
				" Treat [PII_*] tokens as opaque identifiers that must pass through unchanged.",
			"gpt":     piiInstructionDefault,
			"default": piiInstructionDefault,
		},
		PackDecayRate: 0.05,
		PatternPacks: []PatternPack{
			{Pack: "GLOBAL", Enabled: true},
			{Pack: "DE", Enabled: true},
			{Pack: "SECRETS", Enabled: true},
			{Pack: "FR", Enabled: false},
			{Pack: "NL", Enabled: false},
			{Pack: "FINANCE_EU", Enabled: false},
			{Pack: "HEALTHCARE", Enabled: false},
			{Pack: "US", Enabled: false},
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

// loadEnvString sets *dst to the value of the named env var if it is non-empty.
func loadEnvString(name string, dst *string) {
	if v := os.Getenv(name); v != "" {
		*dst = v
	}
}

// loadEnvInt sets *dst to the parsed integer value of the named env var if valid.
func loadEnvInt(name string, dst *int) {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

// loadEnvIntPositive sets *dst to the parsed integer if valid and > 0.
func loadEnvIntPositive(name string, dst *int) {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			*dst = n
		}
	}
}

// loadEnvFloat sets *dst to the parsed float value of the named env var if valid.
func loadEnvFloat(name string, dst *float64) {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			*dst = f
		}
	}
}

// loadEnvBoolFalse sets *dst to false if the named env var equals "false".
func loadEnvBoolFalse(name string, dst *bool) {
	if os.Getenv(name) == "false" {
		*dst = false
	}
}

func loadEnv(cfg *Config) {
	loadEnvInt("PROXY_PORT", &cfg.ProxyPort)
	loadEnvInt("MANAGEMENT_PORT", &cfg.ManagementPort)
	loadEnvString("OLLAMA_ENDPOINT", &cfg.OllamaEndpoint)
	loadEnvString("OLLAMA_MODEL", &cfg.OllamaModel)
	loadEnvBoolFalse("USE_AI_DETECTION", &cfg.UseAIDetection)
	loadEnvFloat("AI_CONFIDENCE_THRESHOLD", &cfg.AIConfidence)
	loadEnvIntPositive("OLLAMA_MAX_CONCURRENT", &cfg.OllamaMaxConcurrent)
	loadEnvString("LOG_LEVEL", &cfg.LogLevel)
	loadEnvString("CA_CERT_FILE", &cfg.CACertFile)
	loadEnvString("CA_KEY_FILE", &cfg.CAKeyFile)
	loadEnvString("BIND_ADDRESS", &cfg.BindAddress)
	loadEnvString("MANAGEMENT_TOKEN", &cfg.ManagementToken)
	loadEnvString("UPSTREAM_PROXY", &cfg.UpstreamProxy)
	loadEnvString("OLLAMA_CACHE_FILE", &cfg.OllamaCacheFile)
}
