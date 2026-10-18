package anonymizer

import "encoding/json"

// legacyAnonymizeJSON is the json.Unmarshal/json.Marshal implementation of
// AnonymizeJSON that AnonymizeJSONStream replaced, kept verbatim (apart from
// names) as the reference oracle for differential and fuzz tests. It parses the body as JSON, walks the string values, and
// anonymizes them. Non-JSON bodies are treated as plain text.
// When PII tokens are inserted, a system instruction is injected into the
// request to prevent the LLM from substituting plausible-looking fake values
// in place of the tokens.
func legacyAnonymizeJSON(a *Anonymizer, body []byte, requestID string) []byte {
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

	anonymized := legacyWalkValue(a, doc, requestID)

	// If any tokens were recorded for this request, inject a system instruction
	// so the LLM knows to reproduce tokens verbatim.
	if m, ok := anonymized.(map[string]any); ok && requestID != "" {
		a.sessionMu.RLock()
		tokenCount := len(a.sessions[requestID])
		a.sessionMu.RUnlock()
		if tokenCount > 0 {
			legacyInjectPIIInstruction(m, a.resolvePIIInstruction(model))
		}
	}

	out, err := json.Marshal(anonymized)
	if err != nil {
		return body // fallback: return original
	}
	return out
}

// legacyInjectPIIInstruction appends the given instruction to the request's system
// prompt. It handles two API shapes:
//
//   - Anthropic messages API: top-level "system" field (string or content-block array)
//   - OpenAI-compatible API:  first "messages" entry with role "system"
//
// If neither shape is found, the function is a no-op — non-chat endpoints
// (embeddings, completions) don't carry a system prompt to inject into.
func legacyInjectPIIInstruction(doc map[string]any, instruction string) {
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

// legacyWalkValue recursively anonymizes string leaves in a JSON-decoded value.
func legacyWalkValue(a *Anonymizer, v any, requestID string) any {
	switch val := v.(type) {
	case string:
		return a.AnonymizeText(val, requestID)
	case []any:
		for i, item := range val {
			val[i] = legacyWalkValue(a, item, requestID)
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
				val[k] = legacyWalkValue(a, item, requestID)
			}
		}
		return val
	}
	return v
}
