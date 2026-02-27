// Package anonymizer detects and replaces PII in text.
// Detection runs in two stages:
//  1. Fast regex pass for structured patterns (email, phone, SSN, etc.).
//     Each pattern carries a base confidence score reflecting how specifically
//     the regex identifies the target PII type.
//  2. AI pass via Ollama — triggered only when the regex stage produces at
//     least one low-confidence match (or no matches at all, which means the
//     text may still contain AI-detectable PII such as names or medical terms).
//
// The AI pass is fully asynchronous on cache-miss:
//   - Cache hit  → detections applied immediately to the current request.
//   - Cache miss → a background goroutine dispatches the Ollama query and
//     stores the result; the current request proceeds with regex-only output.
//     Subsequent requests for identical text will benefit from the warm cache.
//
// An in-flight deduplication map prevents multiple concurrent goroutines from
// querying Ollama for the same content hash.
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

	"ai-anonymizing-proxy/internal/metrics"
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

// pattern pairs a compiled regex with its PII type and a base confidence score.
// Confidence reflects how specifically the regex identifies the target PII type:
// high scores mean low false-positive risk; low scores indicate ambiguous patterns
// where AI verification adds meaningful value.
type pattern struct {
	re         *regexp.Regexp
	piiType    PIIType
	confidence float64
}

// Anonymizer holds compiled patterns and the Ollama client config.
type Anonymizer struct {
	patterns    []pattern
	ollamaURL   string
	ollamaModel string
	useAI       bool
	aiThreshold float64
	m           *metrics.Metrics // nil = no metrics collection

	cacheMu sync.RWMutex
	cache   map[string][]ollamaDetection // keyed by md5(text)

	inflightMu sync.Mutex
	inflight   map[string]bool // prevents duplicate concurrent Ollama queries

	ollamaSem chan struct{} // limits concurrent Ollama queries

	sessionMu sync.RWMutex
	sessions  map[string]map[string]string // sessionID → token → original
}

// New creates an Anonymizer with the given options.
// Pass a non-nil m to collect performance metrics; pass nil to disable.
func New(ollamaEndpoint, ollamaModel string, useAI bool, aiThreshold float64, ollamaMaxConcurrent int, m *metrics.Metrics) *Anonymizer {
	if ollamaMaxConcurrent < 1 {
		ollamaMaxConcurrent = 1
	}
	a := &Anonymizer{
		ollamaURL:   ollamaEndpoint + "/api/generate",
		ollamaModel: ollamaModel,
		useAI:       useAI,
		aiThreshold: aiThreshold,
		m:           m,
		cache:     make(map[string][]ollamaDetection),
		inflight:  make(map[string]bool),
		ollamaSem: make(chan struct{}, ollamaMaxConcurrent),
		sessions:  make(map[string]map[string]string),
	}
	a.compilePatterns()
	return a
}

func (a *Anonymizer) compilePatterns() {
	// Confidence scores are assigned per Presidio / CHPDA conventions:
	//   0.90+ → highly specific format; regex false-positive rate is very low
	//   0.70–0.89 → moderately specific; some ambiguity possible
	//   below 0.70 → broad pattern with meaningful false-positive risk
	// Any match below aiThreshold triggers async Ollama for the whole text.
	specs := []struct {
		expr       string
		piiType    PIIType
		confidence float64
	}{
		// Email: unambiguous structural markers (@, domain, TLD)
		{`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`, PIIEmail, 0.95},
		// API key: requires keyword prefix + long token — very specific
		{`(?i)(?:api[_\-]?key|token|secret|bearer)[\s"':=]+([a-zA-Z0-9_\-.]{20,})`, PIIAPIKey, 0.90},
		// SSN: structured hyphenated format
		{`\b(?:\d{3}-?\d{2}-?\d{4}|\d{9})\b`, PIISSN, 0.85},
		// Credit card: 16-digit block pattern
		{`\b(?:\d{4}[\-\s]?){3}\d{4}\b`, PIICreditCard, 0.85},
		// Street address: requires street-type suffix keyword
		{`(?i)\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b`, PIIAddress, 0.75},
		// IP address: matches version numbers and other numeric quads — moderate
		{`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, PIIIPAddress, 0.70},
		// Phone: very broad — matches many numeric sequences that are not phones
		{`(\+?1?[\-.\s]?)?\(?([0-9]{3})\)?[\-.\s]?([0-9]{3})[\-.\s]?([0-9]{4})`, PIIPhone, 0.65},
		// ZIP code: 5 digits match countless non-PII numbers
		{`\b\d{5}(?:-\d{4})?\b`, PIIAddress, 0.40},
	}
	for _, s := range specs {
		re, err := regexp.Compile(s.expr)
		if err != nil {
			log.Printf("[ANONYMIZER] Warning: could not compile pattern %q: %v", s.expr, err)
			continue
		}
		a.patterns = append(a.patterns, pattern{re: re, piiType: s.piiType, confidence: s.confidence})
	}
}

// AnonymizeText replaces all detected PII in the given string.
// sessionID is used to record token→original mappings for later de-anonymization.
//
// Flow:
//  1. Regex pass — replace structured PII, track minimum match confidence.
//  2. If useAI is enabled and minConfidence < aiThreshold (or no matches):
//     a. Cache hit  → apply AI detections immediately.
//     b. Cache miss → dispatch async Ollama goroutine; return regex-only result.
func (a *Anonymizer) AnonymizeText(text, sessionID string) string {
	if text == "" {
		return text
	}

	result := text
	minConfidence := 1.0 // assume perfect until a low-confidence pattern fires
	anyMatch := false

	// Stage 1: regex pass with per-match confidence tracking.
	for _, p := range a.patterns {
		matched := false
		result = p.re.ReplaceAllStringFunc(result, func(match string) string {
			matched = true
			token := a.replacement(p.piiType, match)
			a.recordMapping(sessionID, token, match)
			return token
		})
		if matched {
			anyMatch = true
			if p.confidence < minConfidence {
				minConfidence = p.confidence
			}
		}
	}

	// Stage 2: AI pass — only when enabled and regex confidence is insufficient.
	// If no regex match occurred at all (minConfidence stays 1.0) we treat the
	// text as unscored (confidence = 0.0) because it may still contain
	// AI-detectable PII such as names, medical terms, or salary figures.
	if !a.useAI {
		return result
	}
	effectiveConfidence := minConfidence
	if !anyMatch {
		effectiveConfidence = 0.0
	}
	if effectiveConfidence >= a.aiThreshold {
		return result // regex caught everything with sufficient confidence
	}

	cacheKey := fmt.Sprintf("%x", md5.Sum([]byte(text))) // #nosec G401 -- cache key, not crypto

	a.cacheMu.RLock()
	cached, hit := a.cache[cacheKey]
	a.cacheMu.RUnlock()

	if hit {
		// Apply cached AI detections immediately.
		result = a.applyDetections(result, sessionID, cached)
	} else {
		// Fire-and-forget: populate cache for future requests.
		a.dispatchOllamaAsync(text, cacheKey)
		// Current request proceeds with regex-only result.
	}

	return result
}

// applyDetections applies a set of ollamaDetections to text, recording session
// mappings for all matches that meet the confidence threshold.
func (a *Anonymizer) applyDetections(text, sessionID string, detections []ollamaDetection) string {
	result := text
	for _, d := range detections {
		if d.Confidence >= a.aiThreshold && d.Original != "" {
			token := a.replacement(d.PIIType, d.Original)
			a.recordMapping(sessionID, token, d.Original)
			result = strings.ReplaceAll(result, d.Original, token)
		}
	}
	return result
}

// dispatchOllamaAsync fires a background goroutine to query Ollama for text
// and store the result in the cache. An in-flight map prevents duplicate
// concurrent queries for the same cacheKey.
func (a *Anonymizer) dispatchOllamaAsync(text, cacheKey string) {
	a.inflightMu.Lock()
	if a.inflight[cacheKey] {
		a.inflightMu.Unlock()
		return // already in progress
	}
	a.inflight[cacheKey] = true
	a.inflightMu.Unlock()

	go func() {
		defer func() {
			a.inflightMu.Lock()
			delete(a.inflight, cacheKey)
			a.inflightMu.Unlock()
		}()

		// Acquire semaphore; drop the request if Ollama is already busy.
		select {
		case a.ollamaSem <- struct{}{}:
			defer func() { <-a.ollamaSem }()
		default:
			log.Printf("[ANONYMIZER] Ollama busy, skipping background query for key %s", cacheKey[:8])
			return
		}

		detections, err := a.queryOllamaHTTP(text)
		if err != nil {
			log.Printf("[ANONYMIZER] async Ollama query failed: %v", err)
			return
		}

		a.cacheMu.Lock()
		a.cache[cacheKey] = detections
		a.cacheMu.Unlock()

		log.Printf("[ANONYMIZER] async Ollama cache populated for key %s (%d detections)", cacheKey[:8], len(detections))
	}()
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

// recordMapping stores token → original in the session map.
func (a *Anonymizer) recordMapping(sessionID, token, original string) {
	if sessionID == "" {
		return
	}
	a.sessionMu.Lock()
	if a.sessions[sessionID] == nil {
		a.sessions[sessionID] = make(map[string]string)
	}
	a.sessions[sessionID][token] = original
	a.sessionMu.Unlock()
	if a.m != nil {
		a.m.TokensReplaced.Add(1)
	}
}

// DeanonymizeText reverses all token replacements recorded for sessionID.
func (a *Anonymizer) DeanonymizeText(text, sessionID string) string {
	if sessionID == "" || text == "" {
		return text
	}
	a.sessionMu.RLock()
	tokenMap := a.sessions[sessionID]
	a.sessionMu.RUnlock()

	result := text
	for token, original := range tokenMap {
		result = strings.ReplaceAll(result, token, original)
	}
	if a.m != nil && len(tokenMap) > 0 {
		a.m.TokensDeanonymized.Add(int64(len(tokenMap)))
	}
	return result
}

// DeleteSession removes the token map for a completed request.
func (a *Anonymizer) DeleteSession(sessionID string) {
	if sessionID == "" {
		return
	}
	a.sessionMu.Lock()
	delete(a.sessions, sessionID)
	a.sessionMu.Unlock()
}

// maxTokenLen is the length of the longest possible anonymization token.
// Used as the overlap window in StreamingDeanonymize to prevent tokens
// from being split across chunk boundaries.
// Longest token: "user<8hex>@example.com" = 24 chars; 64 gives comfortable headroom.
const maxTokenLen = 64

// StreamingDeanonymize wraps src in a reader that replaces tokens on-the-fly
// without buffering the full body. Use this for SSE / chunked responses where
// io.ReadAll would block until the upstream closes the connection.
//
// A snapshot of the session token map is taken immediately (under the read
// lock) so the goroutine is unaffected by a later DeleteSession call.
//
// Replacement is done in chunks with a maxTokenLen-byte overlap window carried
// between reads. This guarantees tokens cannot straddle a chunk boundary
// regardless of how the upstream transports frames the data — avoiding the
// bufio.Scanner ErrTooLong failure that occurred when SSE data lines exceeded
// the scanner's fixed 256 KiB buffer cap.
func (a *Anonymizer) StreamingDeanonymize(src io.ReadCloser, sessionID string) io.ReadCloser {
	a.sessionMu.RLock()
	raw := a.sessions[sessionID]
	tokenMap := make(map[string]string, len(raw))
	for k, v := range raw {
		tokenMap[k] = v
	}
	a.sessionMu.RUnlock()

	if len(tokenMap) == 0 {
		return src
	}

	if a.m != nil {
		a.m.TokensDeanonymized.Add(int64(len(tokenMap)))
	}

	pairs := make([]string, 0, len(tokenMap)*2)
	for token, original := range tokenMap {
		pairs = append(pairs, token, original)
	}
	replacer := strings.NewReplacer(pairs...)

	pr, pw := io.Pipe()
	go func() {
		defer src.Close() //nolint:errcheck // best-effort close
		defer pw.Close()  //nolint:errcheck // pipe closed on goroutine exit; error unrecoverable

		const chunkSize = 32 * 1024
		buf := make([]byte, chunkSize)
		// overlap holds the tail of the previous chunk that may contain an
		// incomplete token. It is prepended to each new read before processing.
		var overlap []byte

		for {
			n, readErr := src.Read(buf)
			if n > 0 {
				// Work on overlap + new data
				window := append(overlap, buf[:n]...) //nolint:gocritic // intentional: grow overlap into window

				// Safe region: everything except the last maxTokenLen bytes,
				// which become the next overlap. At EOF (readErr != nil) the
				// entire window is safe — flush it all.
				safeEnd := len(window)
				if readErr == nil {
					if safeEnd > maxTokenLen {
						safeEnd = len(window) - maxTokenLen
					} else {
						// Window smaller than a token; accumulate in overlap
						// until we have enough context or reach EOF.
						safeEnd = 0
					}
				}

				if safeEnd > 0 {
					replaced := replacer.Replace(string(window[:safeEnd]))
					if _, werr := pw.Write([]byte(replaced)); werr != nil {
						return
					}
				}

				// Carry forward the unprocessed tail
				overlap = append(overlap[:0], window[safeEnd:]...)
			}

			if readErr != nil {
				// Flush any remaining overlap that was held back.
				if len(overlap) > 0 {
					replaced := replacer.Replace(string(overlap))
					pw.Write([]byte(replaced)) //nolint:errcheck // pipe; error unrecoverable
				}
				if readErr != io.EOF {
					log.Printf("[ANONYMIZER] StreamingDeanonymize read error: %v", readErr)
					pw.CloseWithError(readErr) //nolint:errcheck // pipe error propagated
				}
				return
			}
		}
	}()
	return pr
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

// queryOllamaHTTP sends a single synchronous request to the Ollama HTTP API
// and returns the parsed detections. It does not consult or update the cache;
// callers are responsible for cache management.
func (a *Anonymizer) queryOllamaHTTP(text string) ([]ollamaDetection, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	return detections, nil
}
