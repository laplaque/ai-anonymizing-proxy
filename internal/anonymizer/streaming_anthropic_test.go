package anonymizer

import (
	"encoding/json"
	"strings"
	"testing"
)

// --- Managed Agents API event tests (issue #107) ---

// makeAgentMessage builds an SSE line for an agent.message event with text content.
func makeAgentMessage(texts ...string) string {
	content := make([]agentContentBlock, len(texts))
	for i, t := range texts {
		content[i] = agentContentBlock{Type: "text", Text: t}
	}
	event := map[string]any{
		"type":         "agent.message",
		"id":           "evt_test_123",
		"content":      content,
		"processed_at": "2026-05-01T10:00:00Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

// makeAgentToolResult builds an SSE line for an agent.tool_result event.
func makeAgentToolResult(texts ...string) string {
	content := make([]agentContentBlock, len(texts))
	for i, t := range texts {
		content[i] = agentContentBlock{Type: "text", Text: t}
	}
	event := map[string]any{
		"type":         "agent.tool_result",
		"id":           "evt_test_456",
		"tool_use_id":  "tu_test_789",
		"content":      content,
		"processed_at": "2026-05-01T10:00:01Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

// makeAgentMCPToolResult builds an SSE line for an agent.mcp_tool_result event.
func makeAgentMCPToolResult(texts ...string) string {
	content := make([]agentContentBlock, len(texts))
	for i, t := range texts {
		content[i] = agentContentBlock{Type: "text", Text: t}
	}
	event := map[string]any{
		"type":            "agent.mcp_tool_result",
		"id":              "evt_test_mcp",
		"mcp_tool_use_id": "mtu_test_101",
		"content":         content,
		"processed_at":    "2026-05-01T10:00:02Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

// makeAgentToolUse builds an SSE line for an agent.tool_use event with input.
func makeAgentToolUse(name string, input map[string]any) string {
	event := map[string]any{
		"type":         "agent.tool_use",
		"id":           "evt_test_tu",
		"name":         name,
		"input":        input,
		"processed_at": "2026-05-01T10:00:03Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

// makeAgentCustomToolUse builds an SSE line for an agent.custom_tool_use event.
func makeAgentCustomToolUse(name string, input map[string]any) string {
	event := map[string]any{
		"type":         "agent.custom_tool_use",
		"id":           "evt_test_ctu",
		"name":         name,
		"input":        input,
		"processed_at": "2026-05-01T10:00:04Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

// makeAgentThinking builds an SSE line for an agent.thinking event (no text).
func makeAgentThinking() string {
	event := map[string]any{
		"type":         "agent.thinking",
		"id":           "evt_test_think",
		"processed_at": "2026-05-01T10:00:05Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

func TestAgentMessageTokenReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := makeAgentMessage("Hello " + token + " how are you?")
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("agent.message token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("agent.message still contains token:\n%s", got)
	}
}

func TestAgentMessageMultipleContentBlocks(t *testing.T) {
	token1 := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	token2 := "[PII_PHONE_a1b2c3d4e5f6a7b8]"
	tokenMap := map[string]string{
		token1: "earl@example.com",
		token2: "+49 170 1234567",
	}

	sseInput := makeAgentMessage("Contact: "+token1, "Phone: "+token2)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if strings.Contains(got, token1) {
		t.Errorf("token1 not replaced:\n%s", got)
	}
	if strings.Contains(got, token2) {
		t.Errorf("token2 not replaced:\n%s", got)
	}
	if !strings.Contains(got, "earl@example.com") {
		t.Errorf("original1 not present:\n%s", got)
	}
	if !strings.Contains(got, "+49 170 1234567") {
		t.Errorf("original2 not present:\n%s", got)
	}
}

func TestAgentToolResultTokenReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := makeAgentToolResult("File content: " + token)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("agent.tool_result token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("agent.tool_result still contains token:\n%s", got)
	}
}

func TestAgentMCPToolResultTokenReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	sseInput := makeAgentMCPToolResult("Result: " + token)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("agent.mcp_tool_result token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("agent.mcp_tool_result still contains token:\n%s", got)
	}
}

func TestAgentToolUseInputReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	input := map[string]any{"query": "search for " + token}
	sseInput := makeAgentToolUse("web_search", input)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("agent.tool_use input token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("agent.tool_use still contains token:\n%s", got)
	}
}

func TestAgentCustomToolUseInputReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	input := map[string]any{"email": token}
	sseInput := makeAgentCustomToolUse("send_email", input)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("agent.custom_tool_use input token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("agent.custom_tool_use still contains token:\n%s", got)
	}
}

// makeAgentMCPToolUse builds an SSE line for an agent.mcp_tool_use event.
func makeAgentMCPToolUse(name string, input map[string]any) string {
	event := map[string]any{
		"type":            "agent.mcp_tool_use",
		"id":              "evt_test_mtu",
		"name":            name,
		"mcp_server_name": "test-server",
		"input":           input,
		"processed_at":    "2026-05-01T10:00:06Z",
	}
	b, _ := json.Marshal(event)
	return "data: " + string(b) + "\n"
}

func TestAgentMCPToolUseInputReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	input := map[string]any{"query": "find " + token}
	sseInput := makeAgentMCPToolUse("search_docs", input)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("agent.mcp_tool_use input token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("agent.mcp_tool_use still contains token:\n%s", got)
	}
}

func TestAgentToolUseNestedInputReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	input := map[string]any{
		"options": map[string]any{
			"recipient": token,
			"cc":        []any{"other@example.com", token},
		},
	}
	sseInput := makeAgentToolUse("send_email", input)
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if strings.Contains(got, token) {
		t.Errorf("nested input token not replaced:\n%s", got)
	}
}

func TestAgentMessageMixedContentBlocks(t *testing.T) {
	// Verify that non-text content blocks (image, document) are preserved
	// when a text block in the same array triggers replacement.
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	event := map[string]any{
		"type": "agent.message",
		"id":   "evt_mixed",
		"content": []map[string]any{
			{"type": "text", "text": "Hello " + token},
			{"type": "image", "source": map[string]any{"type": "url", "url": "https://example.com/img.png"}},
			{"type": "text", "text": "No PII here"},
		},
		"processed_at": "2026-05-01T10:00:00Z",
	}
	b, _ := json.Marshal(event)
	sseInput := "data: " + string(b) + "\n"

	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if strings.Contains(got, token) {
		t.Errorf("token not replaced in mixed content:\n%s", got)
	}
	if !strings.Contains(got, original) {
		t.Errorf("original not present in mixed content:\n%s", got)
	}
	// The image block must survive re-serialization.
	if !strings.Contains(got, "https://example.com/img.png") {
		t.Errorf("image block lost during re-serialization:\n%s", got)
	}
	if !strings.Contains(got, "No PII here") {
		t.Errorf("second text block lost:\n%s", got)
	}
}

func TestAgentThinkingPassthrough(t *testing.T) {
	tokenMap := map[string]string{}

	sseInput := makeAgentThinking()
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, "agent.thinking") {
		t.Errorf("agent.thinking event not passed through:\n%s", got)
	}
}

func TestAgentMessageNoTokenNoMutation(t *testing.T) {
	tokenMap := map[string]string{"[PII_EMAIL_c160f8cc4b2e1a3d]": "earl@example.com"}

	sseInput := makeAgentMessage("Hello world, no PII here")
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, "Hello world, no PII here") {
		t.Errorf("text mutated when no token present:\n%s", got)
	}
}

func TestAgentMessageEmptyContent(t *testing.T) {
	// agent.message with empty content array should pass through cleanly.
	event := map[string]any{
		"type":         "agent.message",
		"id":           "evt_empty",
		"content":      []agentContentBlock{},
		"processed_at": "2026-05-01T10:00:00Z",
	}
	b, _ := json.Marshal(event)
	sseInput := "data: " + string(b) + "\n"

	tokenMap := map[string]string{"[PII_EMAIL_c160f8cc4b2e1a3d]": "earl@example.com"}
	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, "agent.message") {
		t.Errorf("empty content event not passed through:\n%s", got)
	}
}

func TestAgentUnknownEventPassthrough(t *testing.T) {
	// A future/unknown agent event type should still pass through with raw replacement.
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	event := map[string]any{
		"type":         "agent.future_event",
		"id":           "evt_future",
		"data":         "some data with " + token,
		"processed_at": "2026-05-01T10:00:00Z",
	}
	b, _ := json.Marshal(event)
	sseInput := "data: " + string(b) + "\n"

	got := readStreamResult(t, sseInput+"\n", tokenMap)

	if !strings.Contains(got, original) {
		t.Errorf("unknown agent event token not replaced:\n%s", got)
	}
	if strings.Contains(got, token) {
		t.Errorf("unknown agent event still contains token:\n%s", got)
	}
}

func TestMixedStreamAgentAndDelta(t *testing.T) {
	// Verify that standard content_block_delta and agent events interleave correctly.
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("x", tokenSuffixLen+10)
	sseInput := makeSSETextDelta(prefix+token+" hello") +
		makeAgentMessage("Agent says: "+token) +
		"\n"

	got := readStreamResult(t, sseInput, tokenMap)

	// Both occurrences should be replaced.
	if strings.Contains(got, token) {
		t.Errorf("mixed stream still contains token:\n%s", got)
	}
	count := strings.Count(got, original)
	if count < 2 {
		t.Errorf("expected at least 2 replacements, got %d:\n%s", count, got)
	}
}

// --- Regression tests for existing content_block_delta handling ---

func TestContentBlockDeltaTextReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("a", tokenSuffixLen+10)
	sseInput := makeSSETextDelta(prefix+token+" done") + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("text_delta token not replaced:\n%s", got)
	}
}

func TestContentBlockDeltaThinkingReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("a", tokenSuffixLen+10)
	sseInput := makeSSEThinkingDelta(prefix+token+" thought") + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("thinking_delta token not replaced:\n%s", got)
	}
}

func TestContentBlockDeltaJSONReplacement(t *testing.T) {
	token := "[PII_EMAIL_c160f8cc4b2e1a3d]"
	original := "earl@example.com"
	tokenMap := map[string]string{token: original}

	prefix := strings.Repeat("a", tokenSuffixLen+10)
	sseInput := makeSSEJsonDelta(prefix+token) + "\n"

	got := readStreamResult(t, sseInput, tokenMap)
	if !strings.Contains(got, original) {
		t.Errorf("input_json_delta token not replaced:\n%s", got)
	}
}
