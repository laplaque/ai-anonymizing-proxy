// Package anonymizer detects and replaces PII in text.
// Detection runs in two stages per matched value:
//  1. Fast regex pass for structured patterns (email, phone, SSN, etc.).
//     Each pattern carries a confidence score. High-confidence matches are
//     tokenized immediately. Low-confidence matches go to stage 2.
//  2. Per-value Ollama cache — consulted for each low-confidence regex match.
//     Cache hit  → use the cached token.
//     Cache miss → apply a deterministic fallback token immediately (PII is
//                  never left unmasked), log the miss, and dispatch an async
//                  Ollama goroutine to warm the cache for future requests.
//
// The cache is keyed by the original PII value, not by a hash of the
// surrounding text. A recurring value (e.g. an IP address) gets a cache hit
// regardless of which message body it appears in.
//
// An in-flight deduplication map prevents multiple concurrent goroutines from
// querying Ollama for the same value.
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

	cache PersistentCache // cross-session Ollama value cache; keyed by original PII value

	inflightMu sync.Mutex
	inflight   map[string]bool // prevents duplicate concurrent Ollama queries

	ollamaSem chan struct{} // limits concurrent Ollama queries

	sessionMu sync.RWMutex
	sessions  map[string]map[string]string // sessionID → token → original

	piiInstructions map[string]string // model family prefix → system instruction
}

// New creates an Anonymizer with the given options.
// Pass a non-nil m to collect performance metrics; pass nil to disable.
// cachePath is the path to the bbolt persistent cache file. If empty, an
// in-memory cache is used (suitable for tests and stateless deployments).
func New(ollamaEndpoint, ollamaModel string, useAI bool, aiThreshold float64, ollamaMaxConcurrent int, m *metrics.Metrics) *Anonymizer {
	return NewWithCache(ollamaEndpoint, ollamaModel, useAI, aiThreshold, ollamaMaxConcurrent, m, "")
}

// defaultCacheCapacity is the maximum number of PII-value→token entries kept in
// the S3-FIFO in-memory layer (and on disk via bbolt). Evicted entries are deleted
// from bbolt so disk usage is bounded to roughly this many entries.
// Override via NewWithCacheAndCapacity for workloads with different cardinality.
const defaultCacheCapacity = 50_000

// NewWithCache creates an Anonymizer with an explicit cache path.
// If cachePath is non-empty, a bbolt persistent cache is opened at that path,
// wrapped with an S3-FIFO in-memory eviction layer (capacity=defaultCacheCapacity).
// If cachePath is empty, an unbounded in-memory cache is used.
func NewWithCache(ollamaEndpoint, ollamaModel string, useAI bool, aiThreshold float64, ollamaMaxConcurrent int, m *metrics.Metrics, cachePath string) *Anonymizer {
	return NewWithCacheAndCapacity(ollamaEndpoint, ollamaModel, useAI, aiThreshold, ollamaMaxConcurrent, m, cachePath, defaultCacheCapacity)
}

// NewWithCacheAndCapacity is like NewWithCache but allows explicit control over
// the S3-FIFO cache capacity (number of entries). Use 0 to disable the S3-FIFO
// layer and fall back to an unbounded in-memory cache (for testing only).
func NewWithCacheAndCapacity(ollamaEndpoint, ollamaModel string, useAI bool, aiThreshold float64, ollamaMaxConcurrent int, m *metrics.Metrics, cachePath string, cacheCapacity int) *Anonymizer {
	if ollamaMaxConcurrent < 1 {
		ollamaMaxConcurrent = 1
	}

	var c PersistentCache
	if cachePath != "" {
		bbolt, err := newBboltCache(cachePath)
		if err != nil {
			log.Printf("[ANONYMIZER] failed to open persistent cache at %q, falling back to memory: %v", cachePath, err)
			c = newMemoryCache()
		} else if cacheCapacity > 0 {
			c = newS3FIFOCache(bbolt, cacheCapacity)
		} else {
			c = bbolt
		}
	} else {
		c = newMemoryCache()
	}

	a := &Anonymizer{
		ollamaURL:   ollamaEndpoint + "/api/generate",
		ollamaModel: ollamaModel,
		useAI:       useAI,
		aiThreshold: aiThreshold,
		m:           m,
		cache:       c,
		inflight:    make(map[string]bool),
		ollamaSem:   make(chan struct{}, ollamaMaxConcurrent),
		sessions:    make(map[string]map[string]string),
	}
	a.compilePatterns()
	return a
}

// Close releases resources held by the anonymizer, including the persistent cache.
// Must be called when the anonymizer is shut down.
func (a *Anonymizer) Close() error {
	return a.cache.Close()
}

// SetPIIInstructions configures the per-model-family system instructions injected
// when PII tokens are present. Keys are model family prefixes (e.g. "claude", "gpt");
// the special key "default" is used when no prefix matches.
func (a *Anonymizer) SetPIIInstructions(instructions map[string]string) {
	a.piiInstructions = instructions
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
		// IPv6: all RFC 5952 compressed and uncompressed forms.
		// The alternation is ordered longest-first so greedy matching picks the
		// most complete address. Confidence is high because the colon-hex syntax
		// is structurally unambiguous and never appears in normal prose.
		{`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}` +
			`|(?:[0-9a-fA-F]{1,4}:){1,7}:` +
			`|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}` +
			`|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}` +
			`|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}` +
			`|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}` +
			`|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}` +
			`|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}` +
			`|:(?::[0-9a-fA-F]{1,4}){1,7}` +
			`|::`,
			PIIIPAddress, 0.85},
		// IPv4: matches version numbers and other numeric quads — moderate
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
// For each regex match:
//   - High-confidence (>= aiThreshold): token applied immediately.
//   - Low-confidence (< aiThreshold) with useAI enabled:
//     cache hit  → use cached token.
//     cache miss → apply fallback token, log miss, dispatch async Ollama.
//
// PII is never left unmasked: every match produces a token regardless of
// cache state or Ollama availability.
func (a *Anonymizer) AnonymizeText(text, sessionID string) string {
	if text == "" {
		return text
	}

	result := text
	for _, p := range a.patterns {
		result = p.re.ReplaceAllStringFunc(result, func(match string) string {
			token := a.tokenForMatch(p, match)
			a.recordMapping(sessionID, token, match)
			return token
		})
	}
	return result
}

// tokenForMatch returns the anonymization token for a single regex match.
// High-confidence patterns are tokenized directly. Low-confidence patterns
// consult the persistent cache; on miss a fallback token is applied immediately
// and an async Ollama dispatch warms the cache for future requests.
func (a *Anonymizer) tokenForMatch(p pattern, match string) string {
	if !a.useAI || p.confidence >= a.aiThreshold {
		return a.replacement(p.piiType, match)
	}

	// Low-confidence path: check persistent per-value cache.
	if cached, hit := a.cache.Get(match); hit {
		if a.m != nil {
			a.m.RecordCacheHit(string(p.piiType))
		}
		return cached
	}

	// Cache miss: apply fallback token immediately so PII is never unmasked,
	// then dispatch Ollama async to warm the cache.
	token := a.replacement(p.piiType, match)
	log.Printf("[ANONYMIZER] low-confidence cache miss piiType=%s", p.piiType)
	if a.m != nil {
		a.m.RecordCacheMiss(string(p.piiType))
		a.m.CacheFallbacks.Add(1)
	}
	a.dispatchOllamaAsync(match)
	return token
}

// dispatchOllamaAsync fires a background goroutine to query Ollama for a
// single PII value and store the result in the per-value cache.
// An in-flight map prevents duplicate concurrent queries for the same value.
func (a *Anonymizer) dispatchOllamaAsync(original string) {
	a.inflightMu.Lock()
	if a.inflight[original] {
		a.inflightMu.Unlock()
		return // already in progress
	}
	a.inflight[original] = true
	a.inflightMu.Unlock()

	if a.m != nil {
		a.m.OllamaDispatches.Add(1)
	}

	go func() {
		defer func() {
			a.inflightMu.Lock()
			delete(a.inflight, original)
			a.inflightMu.Unlock()
		}()

		// Acquire semaphore; drop the request if Ollama is already busy.
		select {
		case a.ollamaSem <- struct{}{}:
			defer func() { <-a.ollamaSem }()
		default:
			log.Printf("[ANONYMIZER] Ollama busy, skipping background query for value")
			if a.m != nil {
				a.m.OllamaErrors.Add(1)
			}
			return
		}

		detections, err := a.queryOllamaHTTP(original)
		if err != nil {
			log.Printf("[ANONYMIZER] async Ollama query failed: %v", err)
			if a.m != nil {
				a.m.OllamaErrors.Add(1)
			}
			return
		}

		for _, d := range detections {
			if d.Original != "" && d.Confidence >= a.aiThreshold {
				a.cache.Set(d.Original, a.replacement(d.PIIType, d.Original))
			}
		}

		log.Printf("[ANONYMIZER] async Ollama cache populated for %d value(s)", len(detections))
	}()
}

// defaultPIIInstruction is the fallback system instruction used when no
// model-specific entry is configured via SetPIIInstructions.
const defaultPIIInstruction = "PRIVACY TOKENS: This request contains privacy-preserving placeholders" +
	" matching the pattern [PII_TYPE_XXXXXXXX] where TYPE indicates the kind of" +
	" information (e.g. EMAIL, PHONE, SSN) and XXXXXXXX is an 8-character hex hash." +
	" You MUST reproduce every such token EXACTLY as written in your response." +
	" Do NOT replace them with example values or any other substitutes." +
	" Treat [PII_*] tokens as opaque identifiers that must pass through unchanged."

// resolvePIIInstruction returns the configured instruction for the given model
// string using prefix matching, falling back to defaultPIIInstruction.
func (a *Anonymizer) resolvePIIInstruction(model string) string {
	for key, instruction := range a.piiInstructions {
		if key == "default" {
			continue
		}
		if len(model) >= len(key) && model[:len(key)] == key {
			return instruction
		}
	}
	if fallback, ok := a.piiInstructions["default"]; ok {
		return fallback
	}
	return defaultPIIInstruction
}

// AnonymizeJSON parses the body as JSON, walks the string values, and
// anonymizes them. Non-JSON bodies are treated as plain text.
// When PII tokens are inserted, a system instruction is injected into the
// request to prevent the LLM from substituting plausible-looking fake values
// in place of the tokens.
func (a *Anonymizer) AnonymizeJSON(body []byte, requestID string) []byte {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		// Not JSON — treat as plain text
		return []byte(a.AnonymizeText(string(body), requestID))
	}
	// Extract model name before walking (walkValue may modify the map).
	model := ""
	if m, ok := doc.(map[string]any); ok {
		if v, ok := m["model"].(string); ok {
			model = v
		}
	}

	anonymized := a.walkValue(doc, requestID)

	// If any tokens were recorded for this request, inject a system instruction
	// so the LLM knows to reproduce tokens verbatim.
	if m, ok := anonymized.(map[string]any); ok && requestID != "" {
		a.sessionMu.RLock()
		tokenCount := len(a.sessions[requestID])
		a.sessionMu.RUnlock()
		if tokenCount > 0 {
			a.injectPIIInstruction(m, a.resolvePIIInstruction(model))
		}
	}

	out, err := json.Marshal(anonymized)
	if err != nil {
		return body // fallback: return original
	}
	return out
}

// injectPIIInstruction appends the given instruction to the request's system
// prompt. It handles two API shapes:
//
//   - Anthropic messages API: top-level "system" field (string or content-block array)
//   - OpenAI-compatible API:  first "messages" entry with role "system"
//
// If neither shape is found, the function is a no-op — non-chat endpoints
// (embeddings, completions) don't carry a system prompt to inject into.
func (a *Anonymizer) injectPIIInstruction(doc map[string]any, instruction string) {
	if instruction == "" {
		return
	}
	// Anthropic API: system is a top-level string or [{type:"text",text:"..."}]
	if sys, ok := doc["system"]; ok {
		switch s := sys.(type) {
		case string:
			if s == "" {
				doc["system"] = instruction
			} else {
				doc["system"] = s + "\n\n" + instruction
			}
			return
		case []any:
			doc["system"] = append(s, map[string]any{
				"type": "text",
				"text": instruction,
			})
			return
		}
	}

	// OpenAI-compatible API: look for a system role message
	if msgs, ok := doc["messages"].([]any); ok {
		for _, m := range msgs {
			if msg, ok := m.(map[string]any); ok && msg["role"] == "system" {
				if content, ok := msg["content"].(string); ok {
					if content == "" {
						msg["content"] = instruction
					} else {
						msg["content"] = content + "\n\n" + instruction
					}
				}
				return
			}
		}
		// No system message — prepend one
		systemMsg := map[string]any{
			"role":    "system",
			"content": instruction,
		}
		doc["messages"] = append([]any{systemMsg}, msgs...)
	}
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
// Tokens use [PII_<TYPE>_<8hex>] notation, e.g. [PII_EMAIL_c160f8cc].
//
// Including the type gives the LLM semantic context ("this was an email") so it
// can reason about the surrounding text correctly, without ever seeing the
// original value. The system instruction injected by injectPIIInstruction
// explicitly prohibits the LLM from substituting plausible-looking values in
// place of tokens, which was the original concern with type-encoded tokens.
//
// Invariant: no token may match any compiled regex pattern, or the proxy will
// re-tokenize its own output in future sessions ("proxy eats itself").
// TestTokenFormatNonRetriggering enforces this.
func (a *Anonymizer) replacement(piiType PIIType, original string) string {
	h := fmt.Sprintf("%x", md5.Sum([]byte(original)))[:8] // #nosec G401 -- deterministic token, not crypto
	return fmt.Sprintf("[PII_%s_%s]", strings.ToUpper(string(piiType)), h)
}

// SessionTokenCount returns the number of tokens recorded for sessionID.
// Returns 0 for unknown or empty sessions.
func (a *Anonymizer) SessionTokenCount(sessionID string) int {
	if sessionID == "" {
		return 0
	}
	a.sessionMu.RLock()
	n := len(a.sessions[sessionID])
	a.sessionMu.RUnlock()
	return n
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

// StreamingDeanonymize wraps src in a reader that replaces PII tokens on-the-fly
// for Anthropic SSE streams.
//
// The Anthropic API streams one or two characters per text_delta event, which
// means a single PII token like [PII_78cabb39] frequently arrives split across
// multiple SSE events:
//
//	{"type":"text_delta","text":"[PII_78cabb"}
//	{"type":"text_delta","text":"39]"}
//
// Raw byte replacement on the SSE envelope cannot match tokens split this way.
// This function therefore:
//  1. Buffers incoming bytes line by line.
//  2. For each complete "data: {...}" SSE line, parses the JSON.
//  3. If the event is a content_block_delta / text_delta, it accumulates the
//     text content into a per-stream text buffer.
//  4. After each text_delta, it checks whether the accumulated buffer contains
//     complete tokens and flushes any replaced text back into the JSON, re-
//     serialising the SSE line before writing it downstream.
//  5. Non-text-delta lines (ping, message_start, thinking_delta, etc.) are
//     passed through verbatim.
//
// A snapshot of the session token map is taken immediately (under the read
// lock) so the goroutine is unaffected by a later DeleteSession call.
func (a *Anonymizer) StreamingDeanonymize(src io.ReadCloser, sessionID string) io.ReadCloser {
a.sessionMu.RLock()
	rawMap := a.sessions[sessionID]
tokenMap := make(map[string]string, len(rawMap))
for k, v := range rawMap {
tokenMap[k] = v
}
a.sessionMu.RUnlock()

log.Printf("[DEANON] StreamingDeanonymize sessionID=%s tokens=%d", sessionID, len(tokenMap))
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

// lineBuf accumulates bytes until we have a complete SSE line.
var lineBuf []byte
// textAccum holds the running text content of consecutive text_delta
// events so tokens split across events can be reassembled.
var textAccum strings.Builder

		const chunkSize = 32 * 1024
buf := make([]byte, chunkSize)

// flushTextAccum writes any accumulated text into pw, replacing tokens.
flushTextAccum := func() {
if textAccum.Len() == 0 {
return
}
_ = textAccum.String() // discard; already written per-event below
textAccum.Reset()
}
_ = flushTextAccum // used via textAccum.Reset() inline

// processLine handles one complete SSE line (without trailing \n).
processLine := func(line []byte) {
// SSE comment or empty line — pass through verbatim.
if len(line) == 0 || line[0] == ':' {
pw.Write(line)         //nolint:errcheck
pw.Write([]byte("\n")) //nolint:errcheck
return
}

// Only "data: ..." lines carry JSON payload.
if !bytes.HasPrefix(line, []byte("data: ")) {
pw.Write([]byte(replacer.Replace(string(line)))) //nolint:errcheck
pw.Write([]byte("\n"))                            //nolint:errcheck
return
}

payload := line[len("data: "):]

// Decode just enough to identify text_delta events.
var envelope struct {
Type  string `json:"type"`
Delta *struct {
Type string `json:"type"`
Text string `json:"text"`
} `json:"delta"`
}
			if err := json.Unmarshal(payload, &envelope); err != nil {
// Not valid JSON (e.g. "[DONE]") — apply replacer then pass through.
pw.Write([]byte("data: "))                    //nolint:errcheck
pw.Write([]byte(replacer.Replace(string(payload)))) //nolint:errcheck
pw.Write([]byte("\n"))                         //nolint:errcheck
return
}

isDeltaText := envelope.Type == "content_block_delta" &&
				envelope.Delta != nil &&
				(envelope.Delta.Type == "text_delta" || envelope.Delta.Type == "thinking_delta")
			if isDeltaText {

// Accumulate text across events so split tokens are reassembled.
textAccum.WriteString(envelope.Delta.Text)
				accumulated := textAccum.String()

// Only flush text that cannot be the start of a pending token.
// Keep a suffix of up to tokenSuffixLen bytes in the accumulator.
const tokenSuffixLen = 26 // len("[PII_CREDITCARD_XXXXXXXX]") == 25; 26 gives one byte margin
flushUpTo := len(accumulated)
if flushUpTo > tokenSuffixLen {
// Scan backward for an open '[' with no matching ']'.
cutAt := len(accumulated) - tokenSuffixLen
for i := len(accumulated) - 1; i >= cutAt; i-- {
if accumulated[i] == '[' {
 closed := strings.ContainsRune(accumulated[i:], ']')
  if !closed {
   cutAt = i
   }
    break
     }
    }
					flushUpTo = cutAt
				} else {
					// Not enough accumulated text yet — keep it all.
					flushUpTo = 0
				}

				toReplace := accumulated[:flushUpTo]
				replaced := replacer.Replace(toReplace)
				if toReplace != replaced {
					log.Printf("[DEANON] text replaced: sessionID=%s tokens=%d", sessionID, len(tokenMap))
				}

				// Re-serialise the event with the replaced text.
				envelope.Delta.Text = replaced
				newPayload, err := json.Marshal(envelope)
				if err != nil {
					// Serialisation failure — write original line unchanged.
					pw.Write(line)         //nolint:errcheck
					pw.Write([]byte("\n")) //nolint:errcheck
					textAccum.Reset()
					return
				}

				pw.Write([]byte("data: ")) //nolint:errcheck
				pw.Write(newPayload)       //nolint:errcheck
				pw.Write([]byte("\n"))     //nolint:errcheck

				// Keep the unprocessed suffix in the accumulator.
				remaining := accumulated[flushUpTo:]
				textAccum.Reset()
				textAccum.WriteString(remaining)
				return
			}

			// Non-text-delta event: flush any pending text accumulation first,
			// then pass the event through with token replacement.
			if textAccum.Len() > 0 {
				flushed := replacer.Replace(textAccum.String())
				// We can't easily re-wrap this into a prior event, so emit a
				// synthetic text_delta carrying the flushed remainder.
				if flushed != "" {
					synth := map[string]any{
						"type":  "content_block_delta",
						"index": 1,
						"delta": map[string]string{"type": "text_delta", "text": flushed},
					}
					if b, err := json.Marshal(synth); err == nil {
						pw.Write([]byte("data: ")) //nolint:errcheck
						pw.Write(b)               //nolint:errcheck
						pw.Write([]byte("\n\n"))   //nolint:errcheck
					}
				}
				textAccum.Reset()
			}

			pw.Write([]byte(replacer.Replace(string(line)))) //nolint:errcheck
			pw.Write([]byte("\n"))                            //nolint:errcheck
		}

		for {
			n, readErr := src.Read(buf)
			if n > 0 {
				for _, b := range buf[:n] {
					if b == '\n' {
						// Strip trailing \r if present (\r\n line endings).
						line := lineBuf
						if len(line) > 0 && line[len(line)-1] == '\r' {
							line = line[:len(line)-1]
						}
						processLine(line)
						lineBuf = lineBuf[:0]
					} else {
						lineBuf = append(lineBuf, b)
					}
				}
			}
			if readErr != nil {
				// Flush any partial line — write replaced bytes directly without an
				// appended newline (the source had no trailing newline).
				if len(lineBuf) > 0 {
					pw.Write([]byte(replacer.Replace(string(lineBuf)))) //nolint:errcheck
				}
				if textAccum.Len() > 0 {
					flushed := replacer.Replace(textAccum.String())
					if flushed != "" {
						synth := map[string]any{
							"type":  "content_block_delta",
							"index": 1,
							"delta": map[string]string{"type": "text_delta", "text": flushed},
						}
						if b, err := json.Marshal(synth); err == nil {
							pw.Write([]byte("data: ")) //nolint:errcheck
							pw.Write(b)               //nolint:errcheck
							pw.Write([]byte("\n\n"))   //nolint:errcheck
						}
					}
					textAccum.Reset()
				}
				if readErr != io.EOF {
					log.Printf("[ANONYMIZER] StreamingDeanonymize read error: %v", readErr)
					pw.CloseWithError(readErr) //nolint:errcheck
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
