package anonymizer

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"strings"
)

// sseEnvelope is the minimal structure needed to identify text_delta events
// in an Anthropic SSE stream.
type sseEnvelope struct {
	Type  string    `json:"type"`
	Delta *sseDelta `json:"delta"`
	Index int       `json:"index"`
}

type sseDelta struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	PartialJSON string `json:"partial_json,omitempty"`
}

// tokenSuffixLen is the number of bytes kept unflushed in the streaming
// accumulator to guard against partial token splits. The longest possible
// token is [PII_CREDITCARD_XXXXXXXXXXXXXXXX] at 33 bytes, derived as:
//
//	5 ("[PII_") + 10 ("CREDITCARD") + 1 ("_") + 16 (hex) + 1 ("]") = 33
//
// We add a margin for trailing text that may follow a token in the same
// delta event. Anthropic streams typically carry 1-2 chars per event, so
// 17 bytes of margin (50 total) is generous.
// Recalculate if any pack introduces a type name longer than 10 chars.
const tokenSuffixLen = 50
