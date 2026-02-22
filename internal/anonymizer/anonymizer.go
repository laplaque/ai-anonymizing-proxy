// Package anonymizer detects and replaces PII in text.
// Detection runs in two stages:
//  1. Fast regex pass for structured patterns (email, phone, SSN, etc.)
//  2. Ollama AI pass for context-aware detection (names, job titles, etc.)
//
// The AI pass is best-effort and async: the regex result is returned immediately
// while Ollama runs in the background. On the next request with identical content
// the cached AI detections are applied on top of the regex result.
// This means zero added latency on cache miss, and full AI+regex on cache hit.
package anonymizer

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- MD5 used for deterministic PII tokens, not cryptographic security
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PIIType classifies the kind of sensitive data found.
type PIIType string

// Supported PII types for detection and anonymization.
const (
	PIIEmail      PIIType = "email"
	PIIPhone      PIIType = "phone"
	PIISSN        PIIType = "ssn"
	PIICreditCard PIIType = "creditCard"
	PIIIPAddress  PIIType = "ipAddress"
	PIIAPIKey     PIIType = "apiKey"
	PIIName       PIIType = "name"
	PIIAddress    PIIType = "address"
	PIIMedical    PIIType = "medical"
	PIISalary     PIIType = "salary"
	PIICompany    PIIType = "company"
	PIIJobTitle   PIIType = "jobTitle"
)

// pattern pairs a compiled regex with its PII type.
type pattern struct {
	re      *regexp.Regexp
	piiType PIIType
}

const maxDetectionCache = 10_000

// Anonymizer holds compiled patterns and the Ollama client config.
type Anonymizer struct {
	patterns    []pattern
	ollamaURL   string
	ollamaModel string
	useAI       bool
	aiThreshold float64

	cacheMu    sync.RWMutex
	cache      map[string][]ollamaDetection // keyed by md5(text)
	cacheOrder []string                     // insertion order for FIFO eviction
	inFlight   sync.Map                     // tracks in-progress Ollama queries (key: cacheKey)
	ollamaSem  chan struct{}                // semaphore: limits concurrent Ollama calls
}

// New creates an Anonymizer with the given options.
func New(ollamaEndpoint, ollamaModel string, useAI bool, aiThreshold float64) *Anonymizer {
	a := &Anonymizer{
		ollamaURL:   ollamaEndpoint + "/api/generate",
		ollamaModel: ollamaModel,
		useAI:       useAI,
		aiThreshold: aiThreshold,
		cache:       make(map[string][]ollamaDetection),
		ollamaSem:   make(chan struct{}, 1), // one Ollama query at a time
	}
	a.compilePatterns()
	return a
}

func (a *Anonymizer) compilePatterns() {
	specs := []struct {
		expr    string
		piiType PIIType
	}{
		{`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`, PIIEmail},
		{`(\+?1?[\-.\s]?)?\(?([0-9]{3})\)?[\-.\s]?([0-9]{3})[\-.\s]?([0-9]{4})`, PIIPhone},
		{`\b(?:\d{3}-?\d{2}-?\d{4}|\d{9})\b`, PIISSN},
		{`\b(?:\d{4}[\-\s]?){3}\d{4}\b`, PIICreditCard},
		{`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, PIIIPAddress},
		{`(?i)(?:api[_\-]?key|token|secret|bearer)[\s"':=]+([a-zA-Z0-9_\-.]{20,})`, PIIAPIKey},
		{`(?i)\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b`, PIIAddress},
		{`\b\d{5}(?:-\d{4})?\b`, PIIAddress}, // ZIP code
	}
	for _, s := range specs {
		re, err := regexp.Compile(s.expr)
		if err != nil {
			log.Printf("[ANONYMIZER] Warning: could not compile pattern %q: %v", s.expr, err)
			continue
		}
		a.patterns = append(a.patterns, pattern{re: re, piiType: s.piiType})
	}
}

// AnonymizeText replaces all detected PII in the given string.
// The requestID is used only for logging; it does not affect output.
//
// Stage 1 (regex) always runs synchronously.
// Stage 2 (Ollama AI) is async best-effort: if detections are cached they are
// applied immediately; otherwise a background query is started and this call
// returns the regex-only result without waiting.
func (a *Anonymizer) AnonymizeText(text, requestID string) string {
	if text == "" {
		return text
	}

	// Stage 1: fast regex replacements (always synchronous)
	result := text
	for _, p := range a.patterns {
		result = p.re.ReplaceAllStringFunc(result, func(match string) string {
			return a.replacement(p.piiType, match)
		})
	}

	// Stage 2: AI-powered detection (async best-effort)
	if a.useAI {
		result = a.applyAIDetectionsAsync(result, requestID)
	}

	return result
}

// AnonymizeJSON parses the body as JSON, walks the string values, and
// anonymizes them. Non-JSON bodies are treated as plain text.
func (a *Anonymizer) AnonymizeJSON(body []byte, requestID string) []byte {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		// Not JSON — treat as plain text
		return []byte(a.AnonymizeText(string(body), requestID))
	}
	anonymized := a.walkValue(doc, requestID)
	out, err := json.Marshal(anonymized)
	if err != nil {
		return body // fallback: return original
	}
	return out
}

// walkValue recursively anonymizes string leaves in a JSON-decoded value.
func (a *Anonymizer) walkValue(v any, requestID string) any {
	switch val := v.(type) {
	case string:
		return a.AnonymizeText(val, requestID)
	case []any:
		for i, item := range val {
			val[i] = a.walkValue(item, requestID)
		}
		return val
	case map[string]any:
		// Skip fields that are structural, not user content
		skip := map[string]bool{
			"model": true, "temperature": true, "max_tokens": true,
			"top_p": true, "stream": true, "n": true,
		}
		for k, item := range val {
			if !skip[k] {
				val[k] = a.walkValue(item, requestID)
			}
		}
		return val
	}
	return v
}

// replacement generates a deterministic anonymised token for a detected value.
func (a *Anonymizer) replacement(piiType PIIType, original string) string {
	h := fmt.Sprintf("%x", md5.Sum([]byte(original)))[:8] // #nosec G401 -- deterministic token, not crypto
	switch piiType {
	case PIIEmail:
		return fmt.Sprintf("user%s@example.com", h)
	case PIIPhone:
		return fmt.Sprintf("+1-555-%s", h[:4])
	case PIISSN:
		return fmt.Sprintf("XXX-XX-%s", h[:4])
	case PIICreditCard:
		return fmt.Sprintf("XXXX-XXXX-XXXX-%s", h[:4])
	case PIIIPAddress:
		return fmt.Sprintf("10.0.0.%d", []byte(h)[0])
	case PIIAPIKey:
		return fmt.Sprintf("[REDACTED_KEY_%s]", h)
	case PIIName:
		return fmt.Sprintf("Person%s", h[:4])
	case PIIAddress:
		return fmt.Sprintf("[ADDRESS_%s]", h)
	case PIIMedical:
		return fmt.Sprintf("[MEDICAL_%s]", h)
	case PIISalary:
		return "$XX,XXX"
	case PIICompany:
		return fmt.Sprintf("Company%s", h[:4])
	case PIIJobTitle:
		return fmt.Sprintf("Role%s", h[:4])
	}
	return fmt.Sprintf("[REDACTED_%s]", h)
}

// --- Ollama integration ---

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

type ollamaDetection struct {
	Original   string  `json:"original"`
	PIIType    PIIType `json:"type"`
	Confidence float64 `json:"confidence"`
}

// applyAIDetectionsAsync applies cached Ollama detections if available and
// schedules a background query for cache misses. Returns immediately in both cases.
func (a *Anonymizer) applyAIDetectionsAsync(text, requestID string) string {
	cacheKey := fmt.Sprintf("%x", md5.Sum([]byte(text))) // #nosec G401 -- cache key, not crypto

	// Cache hit: apply detections now
	a.cacheMu.RLock()
	cached, hit := a.cache[cacheKey]
	a.cacheMu.RUnlock()

	if hit {
		return a.applyDetections(text, cached)
	}

	// Cache miss: kick off background query if not already in flight
	if _, loaded := a.inFlight.LoadOrStore(cacheKey, struct{}{}); !loaded {
		go func() {
			defer a.inFlight.Delete(cacheKey)

			// Acquire semaphore — drop query if Ollama is already busy
			select {
			case a.ollamaSem <- struct{}{}:
				defer func() { <-a.ollamaSem }()
			default:
				log.Printf("[ANONYMIZER] [%s] Ollama busy, skipping background query", requestID)
				return
			}

			_, err := a.queryOllama(text, cacheKey)
			if err != nil {
				log.Printf("[ANONYMIZER] [%s] background Ollama query failed: %v", requestID, err)
			}
		}()
	}

	// Return regex-only result immediately
	return text
}

// applyDetections applies a slice of Ollama detections to text.
func (a *Anonymizer) applyDetections(text string, detections []ollamaDetection) string {
	result := text
	for _, d := range detections {
		if d.Confidence >= a.aiThreshold && d.Original != "" {
			replacement := a.replacement(d.PIIType, d.Original)
			result = strings.ReplaceAll(result, d.Original, replacement)
		}
	}
	return result
}

// queryOllama calls the Ollama API and stores results in the cache.
// cacheKey must be the md5 of text (pre-computed by the caller).
func (a *Anonymizer) queryOllama(text, cacheKey string) ([]ollamaDetection, error) {

	prompt := fmt.Sprintf(`Analyze the following text for PII (personally identifiable information).
Return ONLY a JSON array of detections. Each item must have:
- "original": the exact text found
- "type": one of: email, phone, ssn, creditCard, name, address, medical, salary, company, jobTitle, apiKey
- "confidence": float 0.0-1.0

Text to analyze:
%s

Return ONLY the JSON array, no explanation. Example: [{"original":"John Smith","type":"name","confidence":0.95}]`,
		text)

	reqBody, _ := json.Marshal(ollamaRequest{
		Model:  a.ollamaModel,
		Prompt: prompt,
		Stream: false,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.ollamaURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from trusted config, not user input
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on HTTP response body

	const maxOllamaResponse = 10 << 20 // 10 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOllamaResponse+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxOllamaResponse {
		log.Printf("[ANONYMIZER] Ollama response truncated at %d bytes", maxOllamaResponse)
		body = body[:maxOllamaResponse]
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, fmt.Errorf("ollama response parse error: %w", err)
	}

	// Extract the JSON array from the model's text response
	raw := strings.TrimSpace(ollamaResp.Response)
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array in ollama response")
	}
	raw = raw[start : end+1]

	var detections []ollamaDetection
	if err := json.Unmarshal([]byte(raw), &detections); err != nil {
		return nil, fmt.Errorf("detection parse error: %w", err)
	}

	// Store in cache; evict oldest 25 % of entries when the limit is exceeded.
	a.cacheMu.Lock()
	a.cache[cacheKey] = detections
	a.cacheOrder = append(a.cacheOrder, cacheKey)
	if len(a.cache) > maxDetectionCache {
		evict := maxDetectionCache / 4
		for _, k := range a.cacheOrder[:evict] {
			delete(a.cache, k)
		}
		// Compact cacheOrder: keep only keys still present in the cache map
		// (handles duplicate keys caused by re-insertion after eviction).
		alive := a.cacheOrder[:0]
		for _, k := range a.cacheOrder[evict:] {
			if _, ok := a.cache[k]; ok {
				alive = append(alive, k)
			}
		}
		a.cacheOrder = alive
	}
	a.cacheMu.Unlock()

	return detections, nil
}
