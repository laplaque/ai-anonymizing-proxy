// Package config loads and holds all proxy configuration.
// Settings are layered: defaults → proxy-config.json → environment variables (env vars win).
// Upstream proxy chaining is configured via the UpstreamProxy field / UPSTREAM_PROXY env var.
package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
)

// piiInstructionPrefix is the common prefix for all PII instruction strings.
const piiInstructionPrefix = "PRIVACY TOKENS: This request contains privacy-preserving placeholders" +
	" matching the pattern [PII_TYPE_XXXXXXXXXXXXXXXX] where TYPE indicates the kind of" +
	" information (e.g. EMAIL, PHONE, SSN) and XXXXXXXXXXXXXXXX is a 16-character hex hash. "

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

	// EnabledPacks lists the PII detection packs that are active at startup.
	// Defaults: ["SECRETS", "GLOBAL", "DE"]. All patterns must belong to an
	// enabled pack to participate in detection. Zero enabled packs is fatal.
	EnabledPacks []string `json:"enabledPacks"`

	// PackDecayRate controls the likelihood multiplier decay per pack position.
	// effectiveConfidence = baseConfidence * (1.0 - (position-1) * PackDecayRate)
	// Default: 0.05. Set to 0.0 to disable positional decay.
	PackDecayRate float64 `json:"packDecayRate"`

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
	// Clamp PackDecayRate to [0, 1].
	if cfg.PackDecayRate < 0 {
		log.Printf("[CONFIG] Warning: packDecayRate %f is negative, clamping to 0", cfg.PackDecayRate)
		cfg.PackDecayRate = 0
	}
	if cfg.PackDecayRate > 1 {
		log.Printf("[CONFIG] Warning: packDecayRate %f exceeds 1.0, clamping to 1.0", cfg.PackDecayRate)
		cfg.PackDecayRate = 1
	}
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
		EnabledPacks:        []string{"SECRETS", "GLOBAL", "DE"},
		PackDecayRate:       0.05,
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
			"api.groq.com",
			"api.deepseek.com",
			"api.fireworks.ai",
			"api.x.ai",
			"api.endpoints.anyscale.com",
			"openrouter.ai",
			"api.portkey.ai",
			// Azure OpenAI: {resource}.openai.azure.com
			"*.openai.azure.com",
			// Vertex AI:
			//   global:   aiplatform.googleapis.com (exact)
			//   regional: {region}-aiplatform.googleapis.com (3-label,
			//             hyphen between region and "aiplatform" — see
			//             https://cloud.google.com/vertex-ai/generative-ai/docs/learn/locations).
			//   *.aiplatform.googleapis.com is kept defensively for any
			//   future host that publishes a 4-label form.
			"aiplatform.googleapis.com",
			"*-aiplatform.googleapis.com",
			"*.aiplatform.googleapis.com",
			// Amazon Bedrock: bedrock-runtime.{region}.amazonaws.com
			"bedrock-runtime.*.amazonaws.com",
			"bedrock-agent-runtime.*.amazonaws.com",
		},
		AuthDomains: []string{
			"accounts.google.com",
			"login.microsoftonline.com",
			"auth0.com",
			"okta.com",
			"oauth2.googleapis.com",
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
	}
}

// loadEnvStringSlice sets *dst to a comma-separated list from the named env var if non-empty.
func loadEnvStringSlice(name string, dst *[]string) {
	if v := os.Getenv(name); v != "" {
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		if len(result) > 0 {
			*dst = result
		}
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
	loadEnvStringSlice("ENABLED_PACKS", &cfg.EnabledPacks)
	loadEnvFloat("PACK_DECAY_RATE", &cfg.PackDecayRate)
}
