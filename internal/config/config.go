// Package config loads and holds all proxy configuration.
// Settings are read from environment variables first, then proxy-config.json.
// Go's net/http automatically respects HTTP_PROXY / HTTPS_PROXY env vars,
// so upstream (corporate) proxy chaining requires no extra code here.
package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
)

// Config holds the full proxy configuration.
type Config struct {
	ProxyPort      int     `json:"proxyPort"`
	ManagementPort int     `json:"managementPort"`
	OllamaEndpoint string  `json:"ollamaEndpoint"`
	OllamaModel    string  `json:"ollamaModel"`
	UseAIDetection bool    `json:"useAIDetection"`
	AIConfidence   float64 `json:"aiConfidenceThreshold"`
	LogLevel       string  `json:"logLevel"`

	CACertFile  string `json:"caCertFile"`
	CAKeyFile   string `json:"caKeyFile"`
	BindAddress string `json:"bindAddress"`

	AIAPIDomains []string `json:"aiApiDomains"`
	AuthDomains  []string `json:"authDomains"`
	AuthPaths    []string `json:"authPaths"`
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
		ProxyPort:      8080,
		ManagementPort: 8081,
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "qwen2.5:3b",
		UseAIDetection: true,
		AIConfidence:   0.7,
		LogLevel:       "info",
		CACertFile:     "ca-cert.pem",
		CAKeyFile:      "ca-key.pem",
		BindAddress:    "127.0.0.1",
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
	}
}

func loadFile(cfg *Config, path string) {
	data, err := os.ReadFile(path)
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
}
