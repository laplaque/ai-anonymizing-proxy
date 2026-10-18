package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"ai-anonymizing-proxy/internal/config"
	"ai-anonymizing-proxy/internal/management"
	"ai-anonymizing-proxy/internal/metrics"
)

// Regression tests for issue #153: compressed request bodies must be decoded
// before anonymization, re-encoded with the original content coding, and
// rejected (never text-anonymized or forwarded) when malformed or unsupported.
//
// All values are synthetic. The email uses the reserved example.com domain.

const (
	syntheticEmail  = "jane.doe@example.com"
	syntheticOpaque = "gAAAAABsyntheticOpaqueBlobQUJDREVGR0hJSktMTU5PUFFSU1RVVldY"
)

var emailTokenRE = regexp.MustCompile(`\[PII_EMAIL_[0-9a-f]{16}\]`)

// syntheticResponsesBody is an OpenAI Responses-style request carrying the
// synthetic email in user text and inside inline function-call arguments (a
// JSON document encoded as a JSON string), plus opaque protocol fields that
// must survive anonymization byte-for-byte.
func syntheticResponsesBody(t *testing.T) []byte {
	t.Helper()
	args, err := json.Marshal(map[string]any{"to": syntheticEmail, "subject": "Invoice 42"})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	doc := map[string]any{
		"model": "gpt-test",
		"input": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "Please contact " + syntheticEmail + " about the invoice."},
				},
			},
			map[string]any{
				"type":      "function_call",
				"call_id":   "call_synthetic_001",
				"name":      "send_email",
				"arguments": string(args),
			},
			map[string]any{
				"type":              "reasoning",
				"id":                "rs_synthetic_001",
				"encrypted_content": syntheticOpaque,
			},
		},
		"tools": []any{
			map[string]any{
				"type": "function",
				"name": "send_email",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{"to": map[string]any{"type": "string"}},
				},
			},
		},
		"stream": true,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

// encodeChain applies codings in the order they are listed, mirroring the
// Content-Encoding header semantics, using the libraries directly so the
// tests do not depend on the code under test.
func encodeChain(t *testing.T, data []byte, codings ...string) []byte {
	t.Helper()
	for _, c := range codings {
		var buf bytes.Buffer
		switch c {
		case "gzip", "x-gzip":
			w := gzip.NewWriter(&buf)
			mustWriteClose(t, w, data)
		case "deflate":
			w := zlib.NewWriter(&buf)
			mustWriteClose(t, w, data)
		case "zstd":
			w, err := zstd.NewWriter(&buf)
			if err != nil {
				t.Fatalf("zstd writer: %v", err)
			}
			mustWriteClose(t, w, data)
		case "identity":
			buf.Write(data)
		default:
			t.Fatalf("encodeChain: unknown coding %q", c)
		}
		data = buf.Bytes()
	}
	return data
}

// decodeChain reverses encodeChain.
func decodeChain(t *testing.T, data []byte, codings ...string) []byte {
	t.Helper()
	out, err := decodeChainErr(data, codings...)
	if err != nil {
		t.Fatalf("decodeChain %v: %v", codings, err)
	}
	return out
}

// decodeChainErr is decodeChain for contexts that cannot call t.Fatal, such
// as an upstream handler goroutine.
func decodeChainErr(data []byte, codings ...string) ([]byte, error) {
	for i := len(codings) - 1; i >= 0; i-- {
		var r io.Reader
		switch codings[i] {
		case "gzip", "x-gzip":
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			r = zr
		case "deflate":
			zr, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			r = zr
		case "zstd":
			zr, err := zstd.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			defer zr.Close()
			r = zr
		default:
			return nil, errors.New("unknown coding " + codings[i])
		}
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		data = out
	}
	return data, nil
}

// headerCodings splits a Content-Encoding header value into tokens.
func headerCodings(v string) []string {
	var out []string
	for _, tok := range strings.Split(v, ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func mustWriteClose(t *testing.T, w io.WriteCloser, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// assertAnonymizedResponsesBody checks PII replacement, tool-argument
// validity and opaque-field preservation on a decoded, anonymized body.
func assertAnonymizedResponsesBody(t *testing.T, original, decoded []byte) {
	t.Helper()
	if bytes.Contains(decoded, []byte(syntheticEmail)) {
		t.Fatalf("synthetic email leaked to upstream body: %s", decoded)
	}
	if !emailTokenRE.Match(decoded) {
		t.Fatalf("expected an email token in upstream body: %s", decoded)
	}

	var got, want map[string]any
	if err := json.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("upstream body is not valid JSON: %v", err)
	}
	if err := json.Unmarshal(original, &want); err != nil {
		t.Fatalf("original body is not valid JSON: %v", err)
	}

	input, ok := got["input"].([]any)
	if !ok || len(input) != 3 {
		t.Fatalf("input array changed shape: %#v", got["input"])
	}
	call, _ := input[1].(map[string]any)
	argStr, ok := call["arguments"].(string)
	if !ok {
		t.Fatalf("function_call arguments is no longer a string: %#v", call["arguments"])
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(argStr), &args); err != nil {
		t.Fatalf("function_call arguments no longer valid JSON (%q): %v", argStr, err)
	}
	if to, _ := args["to"].(string); !emailTokenRE.MatchString(to) {
		t.Fatalf("expected tokenized recipient in tool arguments, got %q", to)
	}
	if args["subject"] != "Invoice 42" {
		t.Fatalf("tool argument subject changed: %#v", args["subject"])
	}
	if call["call_id"] != "call_synthetic_001" || call["name"] != "send_email" {
		t.Fatalf("function_call identifiers changed: %#v", call)
	}

	reasoning, _ := input[2].(map[string]any)
	if reasoning["encrypted_content"] != syntheticOpaque || reasoning["id"] != "rs_synthetic_001" {
		t.Fatalf("opaque reasoning fields changed: %#v", reasoning)
	}
	if !reflect.DeepEqual(got["tools"], want["tools"]) {
		t.Fatalf("tools changed:\n got %#v\nwant %#v", got["tools"], want["tools"])
	}
	if got["model"] != want["model"] || got["stream"] != want["stream"] {
		t.Fatalf("model/stream changed: model=%#v stream=%#v", got["model"], got["stream"])
	}
}

// --- anonymizeRequestBody: supported codings ---

func TestAnonymizeRequestBody_ContentCodings(t *testing.T) {
	cases := []struct {
		name       string
		header     []string // Content-Encoding header lines as sent
		chain      []string // codings actually applied, in header order
		wantHeader string   // Content-Encoding forwarded upstream ("" = absent)
	}{
		{"plain", nil, nil, ""},
		{"identity", []string{"identity"}, nil, "identity"},
		{"zstd", []string{"zstd"}, []string{"zstd"}, "zstd"},
		{"zstd uppercase", []string{"ZSTD"}, []string{"zstd"}, "zstd"},
		{"gzip", []string{"gzip"}, []string{"gzip"}, "gzip"},
		{"x-gzip", []string{"x-gzip"}, []string{"gzip"}, "gzip"},
		{"deflate", []string{"deflate"}, []string{"deflate"}, "deflate"},
		{"chain gzip then zstd", []string{"gzip, zstd"}, []string{"gzip", "zstd"}, "gzip, zstd"},
		{"chain split across header lines", []string{"deflate", "gzip"}, []string{"deflate", "gzip"}, "deflate, gzip"},
		{"identity and empty list members", []string{" identity , , zstd "}, []string{"zstd"}, "zstd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestProxyServer(t)
			plain := syntheticResponsesBody(t)
			wire := encodeChain(t, plain, tc.chain...)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"http://api.openai.com/v1/responses", bytes.NewReader(wire))
			req.Header.Set("Content-Type", "application/json")
			for _, v := range tc.header {
				req.Header.Add("Content-Encoding", v)
			}
			req.ContentLength = int64(len(wire))
			req.Header.Set("Content-Length", strconv.Itoa(len(wire)))

			sessionID, err := srv.anonymizeRequestBody(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sessionID == "" {
				t.Fatal("expected a session ID")
			}
			defer srv.anon.DeleteSession(sessionID)

			out, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read rewritten body: %v", err)
			}
			assertFraming(t, req, out)
			if got := strings.Join(req.Header.Values("Content-Encoding"), ", "); got != tc.wantHeader {
				t.Fatalf("Content-Encoding = %q, want %q", got, tc.wantHeader)
			}

			decoded := decodeChain(t, out, tc.chain...)
			assertAnonymizedResponsesBody(t, plain, decoded)

			// The session must be able to restore the original value, proving the
			// replacement happened on decoded content rather than compressed bytes.
			restored := srv.anon.DeanonymizeText(string(decoded), sessionID)
			if !strings.Contains(restored, syntheticEmail) {
				t.Fatalf("de-anonymization did not restore the synthetic email: %s", restored)
			}
		})
	}
}

// assertFraming pins that the length fields and replay body describe exactly
// the bytes that will be transmitted.
func assertFraming(t *testing.T, req *http.Request, sent []byte) {
	t.Helper()
	if req.ContentLength != int64(len(sent)) {
		t.Fatalf("ContentLength = %d, body has %d bytes", req.ContentLength, len(sent))
	}
	if got := req.Header.Get("Content-Length"); got != strconv.Itoa(len(sent)) {
		t.Fatalf("Content-Length header = %q, body has %d bytes", got, len(sent))
	}
	if len(req.TransferEncoding) != 0 {
		t.Fatalf("TransferEncoding = %v, want none (length is known)", req.TransferEncoding)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody must be set so transport retries replay the anonymized body")
	}
	for i := range 2 {
		rc, err := req.GetBody()
		if err != nil {
			t.Fatalf("GetBody #%d: %v", i, err)
		}
		replay, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read GetBody #%d: %v", i, err)
		}
		if !bytes.Equal(replay, sent) {
			t.Fatalf("GetBody #%d replays %d bytes that differ from the %d-byte body", i, len(replay), len(sent))
		}
	}
}

// TestAnonymizeRequestBody_ZstdLiteralPIIRegression reproduces the #153
// failure mode: when the encoder stores literals uncompressed, PII-shaped
// bytes appear verbatim inside the zstd frame. Treating the wire bytes as
// text rewrote that span and corrupted the frame; decoding first must keep
// the frame valid and replace the PII in the decoded JSON.
func TestAnonymizeRequestBody_ZstdLiteralPIIRegression(t *testing.T) {
	srv := newTestProxyServer(t)
	plain := syntheticResponsesBody(t)

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithNoEntropyCompression(true))
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	mustWriteClose(t, zw, plain)
	wire := buf.Bytes()
	if !bytes.Contains(wire, []byte(syntheticEmail)) {
		t.Fatal("precondition: expected the synthetic email to appear verbatim inside the zstd frame")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = int64(len(wire))

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.anon.DeleteSession(sessionID)

	out, _ := io.ReadAll(req.Body)
	assertAnonymizedResponsesBody(t, plain, decodeChain(t, out, "zstd"))
}

// Chunked requests (unknown length) are re-framed with an explicit length.
func TestAnonymizeRequestBody_ChunkedRequestGetsExplicitLength(t *testing.T) {
	srv := newTestProxyServer(t)
	plain := syntheticResponsesBody(t)
	wire := encodeChain(t, plain, "zstd")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.anon.DeleteSession(sessionID)

	out, _ := io.ReadAll(req.Body)
	assertFraming(t, req, out)
	assertAnonymizedResponsesBody(t, plain, decodeChain(t, out, "zstd"))
}

// A client request built with http.NewRequest carries a GetBody that replays
// the ORIGINAL bytes. The transport uses GetBody on retries/redirects, so it
// must be replaced or a retry would send un-anonymized PII upstream.
func TestAnonymizeRequestBody_ReplacesStaleGetBody(t *testing.T) {
	srv := newTestProxyServer(t)
	plain := syntheticResponsesBody(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", bytes.NewReader(plain))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.anon.DeleteSession(sessionID)

	rc, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	replay, _ := io.ReadAll(rc)
	assertAnonymizedResponsesBody(t, plain, replay)
}

// An empty chunked body has nothing to decode or anonymize and is forwarded
// as an explicit zero-length body.
func TestAnonymizeRequestBody_EmptyChunkedBody(t *testing.T) {
	srv := newTestProxyServer(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID != "" {
		t.Fatalf("expected no session for an empty body, got %q", sessionID)
	}
	if req.Body != http.NoBody || req.ContentLength != 0 || len(req.TransferEncoding) != 0 {
		t.Fatalf("expected explicit empty body, got body=%v len=%d te=%v", req.Body, req.ContentLength, req.TransferEncoding)
	}
	if req.Header.Get("Content-Length") != "0" {
		t.Fatalf("Content-Length header = %q, want 0", req.Header.Get("Content-Length"))
	}
	replay, err := req.GetBody()
	if err != nil || replay != http.NoBody {
		t.Fatalf("GetBody = %v, %v; want http.NoBody", replay, err)
	}
}

// The existing size policy caps the WIRE body at maxRequestBody. Decoding must
// not silently add a second cutoff at the same value for the decoded body
// (issue #153; size policy redesign is tracked separately in #152). The large
// value sits in "model", which the anonymizer skips, so the test exercises the
// coding path without regex-scanning tens of MiB.
func TestAnonymizeRequestBody_DecodedSizeNotCappedAtWireLimit(t *testing.T) {
	srv := newTestProxyServer(t)
	big := strings.Repeat("m", maxRequestBody+1024)
	plain := []byte(`{"model":"` + big + `","input":"write to ` + syntheticEmail + `"}`)
	wire := encodeChain(t, plain, "zstd")
	if len(wire) >= maxRequestBody || len(plain) <= maxRequestBody {
		t.Fatalf("precondition: wire=%d decoded=%d limit=%d", len(wire), len(plain), maxRequestBody)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = int64(len(wire))

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("decoded body above the wire limit was rejected: %v", err)
	}
	defer srv.anon.DeleteSession(sessionID)

	out, _ := io.ReadAll(req.Body)
	decoded := decodeChain(t, out, "zstd")
	var doc map[string]string
	if err := json.Unmarshal(decoded, &doc); err != nil {
		t.Fatalf("decoded body invalid: %v", err)
	}
	if len(doc["model"]) != len(big) {
		t.Fatalf("large field truncated: got %d bytes, want %d", len(doc["model"]), len(big))
	}
	if strings.Contains(doc["input"], syntheticEmail) || !emailTokenRE.MatchString(doc["input"]) {
		t.Fatalf("large request was not anonymized: %q", doc["input"])
	}
}

// RFC 9659 bounds the zstd content-coding window at 8 MiB; frames at the
// bound decode, frames above it are rejected before allocation. The encoder
// shrinks the window to the input size, so the body must exceed 8 MiB (the
// filler sits in the anonymizer-skipped "model" field).
func TestAnonymizeRequestBody_ZstdWindowBound(t *testing.T) {
	plain := []byte(`{"model":"` + strings.Repeat("w", 9<<20) + `","input":"hi"}`)
	for _, tc := range []struct {
		name       string
		window     int
		wantHeader uint64 // same value as window, typed for the frame header
		wantOK     bool
	}{
		{"8 MiB accepted", 8 << 20, 8 << 20, true},
		{"16 MiB rejected", 16 << 20, 16 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestProxyServer(t)
			var buf bytes.Buffer
			zw, err := zstd.NewWriter(&buf, zstd.WithWindowSize(tc.window), zstd.WithSingleSegment(false))
			if err != nil {
				t.Fatalf("zstd writer: %v", err)
			}
			mustWriteClose(t, zw, plain)
			var hdr zstd.Header
			if hdrErr := hdr.Decode(buf.Bytes()); hdrErr != nil || hdr.SingleSegment || hdr.WindowSize != tc.wantHeader {
				t.Fatalf("precondition: frame window=%d single=%v err=%v, want window %d", hdr.WindowSize, hdr.SingleSegment, hdrErr, tc.window)
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"http://api.openai.com/v1/responses", bytes.NewReader(buf.Bytes()))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", "zstd")
			req.ContentLength = int64(buf.Len())

			sessionID, err := srv.anonymizeRequestBody(req)
			if sessionID != "" {
				defer srv.anon.DeleteSession(sessionID)
			}
			if tc.wantOK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertRequestBodyError(t, err, http.StatusBadRequest)
		})
	}
}

// --- anonymizeRequestBody: rejections ---

func assertRequestBodyError(t *testing.T, err error, wantStatus int) {
	t.Helper()
	var rbe *requestBodyError
	if !errors.As(err, &rbe) {
		t.Fatalf("expected *requestBodyError with status %d, got %T: %v", wantStatus, err, err)
	}
	if rbe.status != wantStatus {
		t.Fatalf("status = %d, want %d (err: %v)", rbe.status, wantStatus, err)
	}
}

// rejectionCases are request bodies that must be refused before any
// anonymization pass runs. Every malformed body embeds the synthetic email in
// plain bytes so that a plain-text fallback would be observable as a recorded
// token.
func rejectionCases(t *testing.T) []struct {
	name        string
	encoding    string
	contentType string
	body        []byte
	wantStatus  int
} {
	t.Helper()
	plain := syntheticResponsesBody(t)
	zstdBody := encodeChain(t, plain, "zstd")
	gzipBody := encodeChain(t, plain, "gzip")
	pii := []byte("garbage " + syntheticEmail + " garbage")

	var rawDeflate bytes.Buffer
	fw, err := flate.NewWriter(&rawDeflate, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	mustWriteClose(t, fw, plain)

	return []struct {
		name        string
		encoding    string
		contentType string
		body        []byte
		wantStatus  int
	}{
		{"zstd garbage", "zstd", "application/json", pii, http.StatusBadRequest},
		{"zstd truncated frame", "zstd", "application/json", zstdBody[:len(zstdBody)/2], http.StatusBadRequest},
		{"zstd trailing garbage", "zstd", "application/json", append(append([]byte{}, zstdBody...), pii...), http.StatusBadRequest},
		{"gzip garbage", "gzip", "application/json", pii, http.StatusBadRequest},
		{"gzip truncated", "gzip", "application/json", gzipBody[:len(gzipBody)-6], http.StatusBadRequest},
		{"gzip trailing garbage", "gzip", "application/json", append(append([]byte{}, gzipBody...), pii...), http.StatusBadRequest},
		{"deflate garbage", "deflate", "application/json", pii, http.StatusBadRequest},
		{"deflate raw stream without zlib wrapper", "deflate", "application/json", rawDeflate.Bytes(), http.StatusBadRequest},
		{"deflate trailing garbage", "deflate", "application/json",
			append(encodeChain(t, plain, "deflate"), pii...), http.StatusBadRequest},
		{"chain with inner layer malformed", "gzip, zstd", "application/json", encodeChain(t, pii, "zstd"), http.StatusBadRequest},
		{"brotli unsupported", "br", "application/json", pii, http.StatusUnsupportedMediaType},
		{"compress unsupported", "compress", "application/json", pii, http.StatusUnsupportedMediaType},
		{"unsupported member of chain", "gzip, br", "application/json", pii, http.StatusUnsupportedMediaType},
		{"declared JSON but malformed (plain)", "", "application/json", []byte(`{"input":"` + syntheticEmail), http.StatusBadRequest},
		{"declared JSON with params but malformed", "", "Application/JSON; charset=utf-8", pii, http.StatusBadRequest},
		{"declared +json but malformed", "", "application/vnd.synthetic+json", pii, http.StatusBadRequest},
		{"declared JSON, valid zstd, malformed JSON", "zstd", "application/json", encodeChain(t, pii, "zstd"), http.StatusBadRequest},
		{"undeclared zstd bytes sent as JSON", "", "application/json", zstdBody, http.StatusBadRequest},
	}
}

// The detail error stays reachable through the client-facing wrapper so logs
// and callers can tell the failure modes apart.
func TestRequestBodyError_UnwrapsCause(t *testing.T) {
	srv := newTestProxyServer(t)
	wire := append(encodeChain(t, []byte(`{"input":"hi"}`), "deflate"), "tail"...)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "deflate")
	req.ContentLength = int64(len(wire))

	_, err := srv.anonymizeRequestBody(req)
	assertRequestBodyError(t, err, http.StatusBadRequest)
	if !errors.Is(err, errTrailingData) {
		t.Fatalf("expected errors.Is(err, errTrailingData), got %v", err)
	}
	if !strings.HasPrefix(err.Error(), "malformed request body: ") {
		t.Fatalf("unexpected error text %q", err.Error())
	}
}

func TestAnonymizeRequestBody_Rejections(t *testing.T) {
	for _, tc := range rejectionCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestProxyServer(t)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"http://api.openai.com/v1/responses", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			req.ContentLength = int64(len(tc.body))

			sessionID, err := srv.anonymizeRequestBody(req)
			assertRequestBodyError(t, err, tc.wantStatus)
			if sessionID != "" {
				t.Fatalf("expected no session on rejection, got %q", sessionID)
			}
			if n := srv.m.TokensReplaced.Load(); n != 0 {
				t.Fatalf("rejected body reached anonymization: %d token(s) recorded", n)
			}
			if n := srv.m.ErrorsAnonymize.Load(); n != 1 {
				t.Fatalf("ErrorsAnonymize = %d, want 1", n)
			}
		})
	}
}

// Undeclared or non-JSON content types keep the existing behavior: the
// decoded body is anonymized as text.
func TestAnonymizeRequestBody_CompressedNonJSONIsAnonymizedAsText(t *testing.T) {
	srv := newTestProxyServer(t)
	plain := []byte("note: write to " + syntheticEmail)
	wire := encodeChain(t, plain, "gzip")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/notes", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	req.ContentLength = int64(len(wire))

	sessionID, err := srv.anonymizeRequestBody(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.anon.DeleteSession(sessionID)
	out, _ := io.ReadAll(req.Body)
	decoded := string(decodeChain(t, out, "gzip"))
	if strings.Contains(decoded, syntheticEmail) || !emailTokenRE.MatchString(decoded) {
		t.Fatalf("expected decoded text to be anonymized, got %q", decoded)
	}
}

// Encoding the anonymized body cannot fail for in-memory buffers in practice;
// the seam proves such a failure is reported as a 500 and nothing is forwarded.
func TestAnonymizeRequestBody_EncodeFailure(t *testing.T) {
	srv := newTestProxyServer(t)
	orig := zstdEncoderOptions
	t.Cleanup(func() { zstdEncoderOptions = orig })
	zstdEncoderOptions = []zstd.EOption{zstd.WithWindowSize(3)} // invalid: not a power of two

	wire := encodeChain(t, syntheticResponsesBody(t), "zstd")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://api.openai.com/v1/responses", bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = int64(len(wire))

	sessionID, err := srv.anonymizeRequestBody(req)
	assertRequestBodyError(t, err, http.StatusInternalServerError)
	if sessionID != "" {
		t.Fatalf("expected no session on encode failure, got %q", sessionID)
	}
	if n := srv.m.ErrorsAnonymize.Load(); n != 1 {
		t.Fatalf("ErrorsAnonymize = %d, want 1", n)
	}
}

// --- helpers ---

func TestParseContentEncoding(t *testing.T) {
	cases := []struct {
		values  []string
		want    []string
		wantErr bool
	}{
		{nil, nil, false},
		{[]string{""}, nil, false},
		{[]string{"identity"}, nil, false},
		{[]string{"IDENTITY, Identity"}, nil, false},
		{[]string{"gzip"}, []string{"gzip"}, false},
		{[]string{"X-Gzip"}, []string{"gzip"}, false},
		{[]string{"deflate, zstd"}, []string{"deflate", "zstd"}, false},
		{[]string{"zstd", " gzip ,"}, []string{"zstd", "gzip"}, false},
		{[]string{"br"}, nil, true},
		{[]string{"gzip", "compress"}, nil, true},
		{[]string{"gzip;q=1"}, nil, true},
	}
	for _, tc := range cases {
		got, err := parseContentEncoding(tc.values)
		if tc.wantErr {
			assertRequestBodyError(t, err, http.StatusUnsupportedMediaType)
			if !errors.Is(err, errUnsupportedCoding) {
				t.Fatalf("parseContentEncoding(%q): expected errUnsupportedCoding, got %v", tc.values, err)
			}
			for _, v := range tc.values {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("error %q echoes client header value %q", err.Error(), v)
				}
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseContentEncoding(%q): %v", tc.values, err)
		}
		var names []string
		for _, c := range got {
			names = append(names, c.name)
		}
		if !reflect.DeepEqual(names, tc.want) {
			t.Fatalf("parseContentEncoding(%q) = %v, want %v", tc.values, names, tc.want)
		}
	}
}

func TestIsDeclaredJSON(t *testing.T) {
	for ct, want := range map[string]bool{
		"application/json":                    true,
		"Application/JSON; charset=utf-8":     true,
		" application/json ":                  true,
		"application/problem+json":            true,
		"application/vnd.synthetic+JSON; v=1": true,
		"":                                    false,
		"text/plain":                          false,
		"application/jsonl":                   false,
		"application/x-ndjson":                false,
		"multipart/form-data; boundary=x":     false,
	} {
		if got := isDeclaredJSON(ct); got != want {
			t.Errorf("isDeclaredJSON(%q) = %v, want %v", ct, got, want)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestEncodeBody_Errors(t *testing.T) {
	codings := func(t *testing.T, header string) []*contentCoding {
		t.Helper()
		c, err := parseContentEncoding([]string{header})
		if err != nil {
			t.Fatalf("parse %q: %v", header, err)
		}
		return c
	}

	t.Run("write error", func(t *testing.T) {
		// gzip emits its header on the first Write, surfacing the sink error there.
		err := encodeBody(failingWriter{}, []byte("x"), codings(t, "gzip"))
		if err == nil || !strings.Contains(err.Error(), "synthetic write failure") {
			t.Fatalf("expected write failure, got %v", err)
		}
	})
	t.Run("close error", func(t *testing.T) {
		// zstd buffers small input and only writes to the sink on Close.
		err := encodeBody(failingWriter{}, []byte("x"), codings(t, "zstd"))
		if err == nil || !strings.Contains(err.Error(), "synthetic write failure") {
			t.Fatalf("expected close failure, got %v", err)
		}
	})
	t.Run("encoder construction error", func(t *testing.T) {
		orig := zstdEncoderOptions
		t.Cleanup(func() { zstdEncoderOptions = orig })
		zstdEncoderOptions = []zstd.EOption{zstd.WithWindowSize(3)}
		var buf bytes.Buffer
		if err := encodeBody(&buf, []byte("x"), codings(t, "gzip, zstd")); err == nil {
			t.Fatal("expected encoder construction error")
		}
	})
}

func TestDecodeBody_DecoderConstructionError(t *testing.T) {
	orig := zstdDecoderOptions
	t.Cleanup(func() { zstdDecoderOptions = orig })
	zstdDecoderOptions = []zstd.DOption{zstd.WithDecoderMaxWindow(1)} // invalid: below 1 KiB

	c, err := parseContentEncoding([]string{"zstd"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = decodeBody(encodeChain(t, []byte("{}"), "zstd"), c)
	assertRequestBodyError(t, err, http.StatusBadRequest)
}

// --- end-to-end: plain-HTTP path ---

// capturedRequest is what the synthetic upstream observed.
type capturedRequest struct {
	header        http.Header
	contentLength int64
	te            []string
	body          []byte
}

// newCapturingUpstream records each request and echoes its decoded body back
// as the response so the client-side de-anonymization round trip is also
// exercised. The echo is flushed before writing so it is sent without a
// Content-Length: de-anonymization changes the body length and the proxy
// currently forwards a buffered response's upstream Content-Length unchanged,
// a separate response-path defect these request-path tests do not cover.
func newCapturingUpstream(t *testing.T, newServer func(http.Handler) *httptest.Server) (*httptest.Server, chan capturedRequest) {
	t.Helper()
	got := make(chan capturedRequest, 4)
	srv := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- capturedRequest{header: r.Header.Clone(), contentLength: r.ContentLength, te: r.TransferEncoding, body: body}
		decoded, err := decodeChainErr(body, headerCodings(r.Header.Get("Content-Encoding"))...)
		if err != nil {
			http.Error(w, "upstream could not decode request", http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream cannot flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		flusher.Flush()
		_ = json.NewEncoder(w).Encode(map[string]string{"echo": string(decoded)})
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func assertUpstreamReceived(t *testing.T, cr capturedRequest, plain []byte, chain ...string) {
	t.Helper()
	if cr.contentLength != int64(len(cr.body)) {
		t.Fatalf("upstream framing mismatch: Content-Length %d, body %d bytes", cr.contentLength, len(cr.body))
	}
	if len(cr.te) != 0 {
		t.Fatalf("upstream saw Transfer-Encoding %v, want explicit length", cr.te)
	}
	if got, want := cr.header.Get("Content-Encoding"), strings.Join(chain, ", "); got != want {
		t.Fatalf("upstream Content-Encoding = %q, want %q", got, want)
	}
	assertAnonymizedResponsesBody(t, plain, decodeChain(t, cr.body, chain...))
}

func TestHandleHTTP_CompressedRequestEndToEnd(t *testing.T) {
	for _, chain := range [][]string{{"zstd"}, {"gzip"}, {"deflate"}, {"gzip", "zstd"}, nil} {
		t.Run(strings.Join(chain, "+")+"/", func(t *testing.T) {
			upstream, got := newCapturingUpstream(t, httptest.NewServer)
			host := backendHostPort(t, upstream.URL, "http")
			srv := newTestProxyServerAllowLocal(t, []string{"localhost"}, nil)

			plain := syntheticResponsesBody(t)
			wire := encodeChain(t, plain, chain...)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"http://"+host+"/v1/responses", bytes.NewReader(wire))
			req.Header.Set("Content-Type", "application/json")
			if len(chain) > 0 {
				req.Header.Set("Content-Encoding", strings.Join(chain, ", "))
			}
			// Simulate a chunked client upload; the proxy must re-frame it.
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}

			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			assertUpstreamReceived(t, <-got, plain, chain...)
			if !strings.Contains(w.Body.String(), syntheticEmail) {
				t.Fatalf("client response was not de-anonymized: %s", w.Body.String())
			}
		})
	}
}

func TestHandleHTTP_RejectedRequestsNeverReachUpstream(t *testing.T) {
	for _, tc := range rejectionCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			upstream, got := newCapturingUpstream(t, httptest.NewServer)
			host := backendHostPort(t, upstream.URL, "http")
			srv := newTestProxyServerAllowLocal(t, []string{"localhost"}, nil)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"http://"+host+"/v1/responses", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			req.ContentLength = int64(len(tc.body))

			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			assertRejectedResponse(t, w, tc.wantStatus)
			select {
			case cr := <-got:
				t.Fatalf("rejected request reached upstream (%d bytes)", len(cr.body))
			default:
			}
		})
	}
}

func assertRejectedResponse(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status = %d, want %d: %s", w.Code, wantStatus, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte(syntheticEmail)) {
		t.Fatalf("error response echoes request content: %s", w.Body.String())
	}
	if wantStatus == http.StatusUnsupportedMediaType {
		if got := w.Header().Get("Accept-Encoding"); got != "gzip, deflate, zstd" {
			t.Fatalf("415 must advertise supported codings, Accept-Encoding = %q", got)
		}
	}
}

// --- end-to-end: MITM path ---

// TestMITMTunnel_CompressedRequestEndToEnd drives a real TLS client through
// the hijacked CONNECT tunnel with a zstd-encoded request, exactly as an
// intercepted SDK would.
func TestMITMTunnel_CompressedRequestEndToEnd(t *testing.T) {
	upstream, got := newCapturingUpstream(t, httptest.NewTLSServer)
	backendHost := strings.TrimPrefix(upstream.URL, "https://")

	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca-cert.pem")
	cfg := &config.Config{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "test",
		AIAPIDomains:   []string{backendHost},
		CACertFile:     certFile,
		CAKeyFile:      filepath.Join(dir, "ca-key.pem"),
		EnabledPacks:   []string{"GLOBAL"},
	}
	srv := New(cfg, management.NewDomainRegistry(cfg, ""), metrics.New())
	t.Cleanup(func() { _ = srv.Close() })
	srv.transport, _ = upstream.Client().Transport.(*http.Transport)
	if srv.ca == nil {
		t.Fatal("expected CA to be loaded")
	}

	hw := newHijackResponseWriter()
	connect := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://"+backendHost, nil)
	connect.Host = backendHost
	connect.RemoteAddr = "127.0.0.1:12345"
	go srv.handleMITMTunnel(hw, connect, backendHost, backendHost)

	roots := x509.NewCertPool()
	certPEM, readErr := os.ReadFile(certFile)
	if readErr != nil {
		t.Fatalf("read CA cert: %v", readErr)
	}
	roots.AppendCertsFromPEM(certPEM)
	tlsClient := tls.Client(hw.clientConn, &tls.Config{ServerName: backendHost, RootCAs: roots, NextProtos: []string{"http/1.1"}})
	t.Cleanup(func() { _ = tlsClient.Close() })
	if hsErr := tlsClient.HandshakeContext(t.Context()); hsErr != nil {
		t.Fatalf("TLS handshake: %v", hsErr)
	}
	reader := bufio.NewReader(tlsClient)

	plain := syntheticResponsesBody(t)
	send := func(body []byte, encoding string) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+backendHost+"/v1/responses", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", encoding)
		if writeErr := req.Write(tlsClient); writeErr != nil {
			t.Fatalf("write request: %v", writeErr)
		}
		resp, respErr := http.ReadResponse(reader, req)
		if respErr != nil {
			t.Fatalf("read response: %v", respErr)
		}
		return resp
	}

	resp := send(encodeChain(t, plain, "zstd"), "zstd")
	respBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read MITM response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through MITM tunnel, got %d: %s", resp.StatusCode, respBody)
	}
	assertUpstreamReceived(t, <-got, plain, "zstd")
	if !bytes.Contains(respBody, []byte(syntheticEmail)) {
		t.Fatalf("MITM response was not de-anonymized: %s", respBody)
	}

	// A malformed frame on the same keep-alive connection is refused and never forwarded.
	bad := send([]byte("garbage "+syntheticEmail), "zstd")
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed zstd through MITM, got %d", bad.StatusCode)
	}
	select {
	case cr := <-got:
		t.Fatalf("malformed MITM request reached upstream (%d bytes)", len(cr.body))
	default:
	}
}

func TestServeMITMRequest_RejectedRequestsNeverReachUpstream(t *testing.T) {
	for _, tc := range rejectionCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			upstream, got := newCapturingUpstream(t, httptest.NewTLSServer)
			backendHost := strings.TrimPrefix(upstream.URL, "https://")
			srv := newTestProxyServerAllowLocal(t, []string{backendHost}, nil)
			srv.transport, _ = upstream.Client().Transport.(*http.Transport)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				upstream.URL+"/v1/responses", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			req.ContentLength = int64(len(tc.body))

			w := httptest.NewRecorder()
			srv.serveMITMRequest(w, req, mitmContext{host: backendHost, domain: backendHost, remoteHash: "test"})
			assertRejectedResponse(t, w, tc.wantStatus)
			select {
			case cr := <-got:
				t.Fatalf("rejected request reached upstream (%d bytes)", len(cr.body))
			default:
			}
		})
	}
}
