package anonymizer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

// newStreamTestAnonymizer returns a regex-only anonymizer with every pack in
// the documented report-test order and a fixed instruction, so outputs are
// deterministic across instances.
func newStreamTestAnonymizer() *Anonymizer {
	a := NewWithCacheAndCapacity(Options{
		UseAI:         false,
		PackDecayRate: 0,
		EnabledPacks:  []string{"SECRETS", "GLOBAL", "US", "DE", "FR", "NL", "FINANCE_EU", "HEALTHCARE"},
	})
	a.SetVerbose(false)
	a.SetPIIInstructions(map[string]string{"default": "KEEP [PII_*] TOKENS \"verbatim\"\n\tplease"})
	return a
}

// streamJSON runs AnonymizeJSONStream into a buffer and applies the insertion.
func streamJSON(t *testing.T, a *Anonymizer, body, id string) ([]byte, JSONStreamResult) {
	t.Helper()
	var out bytes.Buffer
	res, err := a.AnonymizeJSONStream(&out, strings.NewReader(body), id)
	if err != nil {
		t.Fatalf("AnonymizeJSONStream: %v", err)
	}
	if res.BytesWritten != int64(out.Len()) {
		t.Fatalf("BytesWritten = %d, wrote %d", res.BytesWritten, out.Len())
	}
	b := out.Bytes()
	if res.Insertion != nil {
		off := res.Insertion.Offset
		b = append(append(append([]byte{}, b[:off]...), res.Insertion.Data...), b[off:]...)
	}
	if res.TotalBytes() != int64(len(b)) {
		t.Fatalf("TotalBytes = %d, body is %d", res.TotalBytes(), len(b))
	}
	return b, res
}

// sessionMap returns a copy of the token map recorded for id.
func sessionMap(a *Anonymizer, id string) map[string]string {
	a.sessionMu.RLock()
	defer a.sessionMu.RUnlock()
	m := make(map[string]string, len(a.sessions[id]))
	for k, v := range a.sessions[id] {
		m[k] = v
	}
	return m
}

// streamCorpus covers provider request shapes and JSON edge cases. All
// personal data is synthetic.
var streamCorpus = map[string]string{
	"anthropic string system":          `{"model":"claude-x","system":"You are helpful.","messages":[{"role":"user","content":"mail alice@example.com"}],"max_tokens":100}`,
	"anthropic empty system":           `{"system":"","messages":[{"role":"user","content":"mail alice@example.com"}]}`,
	"anthropic block system":           `{"system":[{"type":"text","text":"Base prompt"}],"messages":[{"role":"user","content":[{"type":"text","text":"call +1 (555) 010-0199 or bob@example.org"}]}]}`,
	"anthropic empty blocks":           `{"system":[],"messages":[{"role":"user","content":"bob@example.org"}]}`,
	"system null falls back":           `{"system":null,"messages":[{"role":"user","content":"bob@example.org"}]}`,
	"openai system message":            `{"model":"gpt-x","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"ssn 123-45-6789"}],"temperature":0.2,"n":1,"stream":true}`,
	"openai empty system":              `{"messages":[{"role":"system","content":""},{"role":"user","content":"bob@example.org"}]}`,
	"openai no system":                 `{"messages":[{"role":"user","content":"bob@example.org"}]}`,
	"openai system non-string content": `{"messages":[{"role":"system","content":[{"type":"text","text":"x"}]},{"role":"user","content":"bob@example.org"}]}`,
	"openai system no content":         `{"messages":[{"content":"bob@example.org","role":"user"},{"role":"system"}]}`,
	"openai role after content":        `{"messages":[{"content":"Base","role":"system"},{"role":"user","content":"bob@example.org"}]}`,
	"messages empty array":             `{"messages":[],"input":"bob@example.org"}`,
	"messages not array":               `{"messages":"bob@example.org"}`,
	"no pii no injection":              `{"system":"plain","messages":[{"role":"user","content":"hello"}]}`,
	"tool history": `{"model":"gpt-x","messages":[` +
		`{"role":"user","content":"Book for carol@example.net"},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"book","arguments":"{\"email\":\"carol@example.net\",\"seats\":2}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":"{\"ok\":true,\"contact\":\"carol@example.net\"}"}],` +
		`"tools":[{"type":"function","function":{"name":"book","parameters":{"type":"object","properties":{"email":{"type":"string"}}}}}]}`,
	"responses api inline input": `{"model":"gpt-x","input":[{"role":"user","content":[` +
		`{"type":"input_text","text":"Summarize for dave@example.com"},` +
		`{"type":"input_image","image_url":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="},` +
		`{"type":"input_file","filename":"a.pdf","file_data":"data:application/pdf;base64,JVBERi0xLjQKJcfsj6IKNSAwIG9iago8PC9MZW5ndGggNiAwIFI+PgpzdHJlYW0K"}]}]}`,
	"skip subtree":        `{"model":"eve@example.com","temperature":{"x":"eve@example.com"},"messages":[{"role":"user","content":"hi"}]}`,
	"nested skip key":     `{"messages":[{"role":"user","content":"hi","n":"eve@example.com"}]}`,
	"top-level array":     `[{"content":"frank@example.com"},"grace@example.com",1,true,null]`,
	"top-level string":    `"heidi@example.com"`,
	"top-level number":    `-12.5e+3`,
	"top-level literal":   `false`,
	"pretty printed":      "{\n  \"system\" : \"Base\" ,\n  \"messages\" : [\n    { \"role\" : \"user\", \"content\" : \"ivan@example.com\" }\n  ]\n}\n",
	"escapes and unicode": `{"messages":[{"role":"user","content":"Caf\u00e9 \"quoted\" \\ back\/slash \ud83d\ude00 judy@example.com \n tab\t <b>&amp;</b>"}]}`,
	"unchanged escapes":   `{"note":"Caf\u00e9 \/ \u2028 <tag> &","messages":[{"role":"user","content":"x"}]}`,
	"lone surrogates":     `{"a":"\ud800 x \udc00 y \ud800\u0041 z \ud800\\n","content":"mallory@example.com"}`,
	"big numbers":         `{"seed":12345678901234567890,"f":1.0,"e":1E2,"neg":-0,"z":0.000001,"content":"oscar@example.com"}`,
	"duplicate keys":      `{"system":"first","system":"second","messages":[{"role":"user","content":"peggy@example.com"}]}`,
	"empty object":        `{}`,
	"empty containers":    `{"a":{},"b":[],"c":[[]],"d":[{}]}`,
	"iban and phone":      `{"messages":[{"role":"user","content":"IBAN DE89370400440532013000, call 030 12345678"}]}`,
	"secret key":          `{"messages":[{"role":"user","content":"token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ done"}]}`,
}

// TestAnonymizeJSONStreamMatchesLegacy is the differential test: for every
// valid corpus document, the streaming output decodes to the same value as
// the json.Unmarshal/json.Marshal implementation it replaced, and records the
// same token map.
func TestAnonymizeJSONStreamMatchesLegacy(t *testing.T) {
	for name, body := range streamCorpus {
		t.Run(name, func(t *testing.T) {
			if !json.Valid([]byte(body)) {
				t.Fatalf("corpus entry is not valid JSON: %s", body)
			}
			streamA, legacyA := newStreamTestAnonymizer(), newStreamTestAnonymizer()
			got, res := streamJSON(t, streamA, body, "sess")
			want := legacyAnonymizeJSON(legacyA, []byte(body), "sess")
			if res.TextFallback {
				t.Fatal("valid JSON took the text fallback")
			}
			assertSameJSON(t, got, want)

			gotTokens, wantTokens := sessionMap(streamA, "sess"), sessionMap(legacyA, "sess")
			if name == "duplicate keys" {
				// Duplicate members are all anonymized by the stream; json.Unmarshal
				// kept only the last, so the legacy map can only be a subset.
				for k, v := range wantTokens {
					if gotTokens[k] != v {
						t.Errorf("token %s missing from stream map", k)
					}
				}
				return
			}
			if !reflect.DeepEqual(gotTokens, wantTokens) {
				t.Errorf("token maps differ:\nstream %v\nlegacy %v", gotTokens, wantTokens)
			}
		})
	}
}

func assertSameJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("stream output is not valid JSON: %v\n%s", err, got)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("legacy output is not valid JSON: %v\n%s", err, want)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("decoded outputs differ:\nstream %s\nlegacy %s", got, want)
	}
}

// TestAnonymizeJSONStreamPreservesBytes pins what the streaming rewrite keeps
// verbatim and the legacy re-marshal did not: key order, whitespace, number
// literals, and the original escaping of strings anonymization leaves alone.
func TestAnonymizeJSONStreamPreservesBytes(t *testing.T) {
	a := newStreamTestAnonymizer()
	body := "{ \"z\": 12345678901234567890, \"a\" : [1.0, 1E2, -0],\n" +
		"  \"html\": \"<b>&</b> \\u00e9 \\/ \\u2028\", \"skip\": {\"model\": \"x\"} }"
	got, res := streamJSON(t, a, body, "")
	if res.Insertion != nil || res.TextFallback {
		t.Fatalf("unexpected result %+v", res)
	}
	if string(got) != body {
		t.Errorf("document without PII changed:\n got %s\nwant %s", got, body)
	}

	// A changed string is re-encoded with minimal escaping; its neighbors keep
	// their original bytes.
	body = `{"keep":"\u00e9\/","content":"x \u00e9 trent@example.com \"q\"","n":1.50}`
	got, _ = streamJSON(t, a, body, "s2")
	tok := a.replacement(PIIEmail, "trent@example.com")
	want := `{"keep":"\u00e9\/","content":"x é ` + tok + ` \"q\"","n":1.50}`
	if string(got) != want {
		t.Errorf("rewrite changed more than the anonymized string:\n got %s\nwant %s", got, want)
	}
}

// TestAnonymizeJSONStreamInsertionPlacement checks the exact bytes produced
// for each injection shape, including pretty-printed input.
func TestAnonymizeJSONStreamInsertionPlacement(t *testing.T) {
	const instr = "INSTR"
	a := newStreamTestAnonymizer()
	a.SetPIIInstructions(map[string]string{"default": instr})
	tok := a.replacement(PIIEmail, "walter@example.com")
	cases := []struct{ name, in, want string }{
		{"string system", `{"system":"S","q":"walter@example.com"}`,
			`{"system":"S\n\nINSTR","q":"` + tok + `"}`},
		{"empty string system", `{"system":"","q":"walter@example.com"}`,
			`{"system":"INSTR","q":"` + tok + `"}`},
		{"system blocks", "{\"system\":[{\"type\":\"text\",\"text\":\"S\"}\n],\"q\":\"walter@example.com\"}",
			"{\"system\":[{\"type\":\"text\",\"text\":\"S\"}\n,{\"type\":\"text\",\"text\":\"INSTR\"}],\"q\":\"" + tok + "\"}"},
		{"empty system blocks", `{"system":[ ],"q":"walter@example.com"}`,
			`{"system":[ {"type":"text","text":"INSTR"}],"q":"` + tok + `"}`},
		{"prepend system message", `{"messages":[ {"role":"user","content":"walter@example.com"}]}`,
			`{"messages":[{"role":"system","content":"INSTR"}, {"role":"user","content":"` + tok + `"}]}`},
		{"empty messages", `{"messages":[],"q":"walter@example.com"}`,
			`{"messages":[{"role":"system","content":"INSTR"}],"q":"` + tok + `"}`},
		{"append to system message", `{"messages":[{"role":"system","content":"S"},{"role":"user","content":"walter@example.com"}]}`,
			`{"messages":[{"role":"system","content":"S\n\nINSTR"},{"role":"user","content":"` + tok + `"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, res := streamJSON(t, a, tc.in, "sess-"+tc.name)
			if res.Insertion == nil {
				t.Fatal("expected an insertion")
			}
			if string(got) != tc.want {
				t.Errorf("\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestAnonymizeJSONStreamTextFallback covers inputs that are not a single
// valid JSON value. A body invalid at its first byte is anonymized exactly as
// AnonymizeText of the whole body (the legacy behavior); otherwise the valid
// prefix keeps its JSON rewrite and the rest is anonymized as text. No
// fallback injects the instruction.
func TestAnonymizeJSONStreamTextFallback(t *testing.T) {
	a := newStreamTestAnonymizer()
	tok := a.replacement(PIIEmail, "victor@example.com")
	cases := []struct{ name, in, want string }{
		{"not json", "not json victor@example.com", "not json " + tok},
		{"empty", "", ""},
		{"whitespace only", " \n", " \n"},
		{"binary", "\x1f\x8b\x08victor@example.com", "\x1f\x8b\x08" + tok},
		{"trailing data", `{"a":"victor@example.com"} {"b":"victor@example.com"}`,
			`{"a":"` + tok + `"} {"b":"` + tok + `"}`},
		{"truncated string", `{"a":"victor@example.com`, `{"a":"` + tok},
		{"truncated object", `{"a":"victor@example.com",`, `{"a":"` + tok + `",`},
		{"control char in string", "{\"a\":\"x\x01victor@example.com\"}", "{\"a\":\"x\x01" + tok + "\"}"},
		{"bad escape", `{"a":"\q victor@example.com"}`, `{"a":"\q ` + tok + `"}`},
		{"truncated escape", `{"a":"\`, `{"a":"\`},
		{"truncated unicode escape", `{"a":"\u00`, `{"a":"\u00`},
		{"bad unicode escape", `{"a":"\u00zz victor@example.com"}`, `{"a":"\u00zz ` + tok + `"}`},
		{"missing colon", `{"a" "victor@example.com"}`, `{"a" "` + tok + `"}`},
		{"missing comma", `{"a":1 "b":"victor@example.com"}`, `{"a":1 "b":"` + tok + `"}`},
		{"trailing comma", `{"a":1,}`, `{"a":1,}`},
		{"unquoted key", `{a:1}`, `{a:1}`},
		{"array missing comma", `["a" "victor@example.com"]`, `["a" "` + tok + `"]`},
		{"bad literal", `{"a":tru}`, `{"a":tru}`},
		{"truncated literal", `[nul`, `[nul`},
		{"bad value start", `{"a":+1}`, `{"a":+1}`},
		{"minus only", `[-]`, `[-]`},
		{"leading zero", `[01]`, `[01]`},
		{"bare fraction", `[1.]`, `[1.]`},
		{"bare exponent", `[1e]`, `[1e]`},
		{"truncated number", `[1.`, `[1.`},
		{"unterminated array", `["victor@example.com"`, `["` + tok + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, res := streamJSON(t, a, tc.in, "sess-fb")
			if !res.TextFallback {
				t.Fatal("expected TextFallback")
			}
			if res.Insertion != nil {
				t.Error("text fallback must not inject the instruction")
			}
			if string(got) != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestAnonymizeJSONStreamNestingLimit verifies documents at the nesting limit
// are rewritten as JSON and deeper ones fall back to text without recursion
// past the limit.
func TestAnonymizeJSONStreamNestingLimit(t *testing.T) {
	a := newStreamTestAnonymizer()
	atLimit := strings.Repeat("[", maxJSONNestingDepth) + `"x"` + strings.Repeat("]", maxJSONNestingDepth)
	got, res := streamJSON(t, a, atLimit, "")
	if res.TextFallback || string(got) != atLimit {
		t.Errorf("document at the nesting limit: fallback=%v, unchanged=%v", res.TextFallback, string(got) == atLimit)
	}

	tooDeep := strings.Repeat("[", maxJSONNestingDepth+1) + strings.Repeat("]", maxJSONNestingDepth+1)
	got, res = streamJSON(t, a, tooDeep, "")
	if !res.TextFallback || string(got) != tooDeep {
		t.Errorf("document past the nesting limit: fallback=%v, unchanged=%v", res.TextFallback, string(got) == tooDeep)
	}
	tooDeepObj := strings.Repeat(`{"a":`, maxJSONNestingDepth+1)
	if _, res = streamJSON(t, a, tooDeepObj, ""); !res.TextFallback {
		t.Error("objects past the nesting limit did not fall back")
	}
}

// TestAnonymizeJSONStreamUTF8 pins string decoding at buffer boundaries and
// for invalid UTF-8: detection sees U+FFFD for invalid bytes (as with
// json.Unmarshal), unchanged strings keep the original bytes, and multi-byte
// runes and escapes that straddle the read buffer decode correctly.
func TestAnonymizeJSONStreamUTF8(t *testing.T) {
	a := newStreamTestAnonymizer()

	unchanged := "{\"a\":\"bad \xff byte\"}"
	if got, _ := streamJSON(t, a, unchanged, ""); string(got) != unchanged {
		t.Errorf("unchanged string with invalid UTF-8 was rewritten: %q", got)
	}

	changed := "{\"a\":\"bad \xff peggy@example.com\"}"
	got, _ := streamJSON(t, a, changed, "u")
	want := "{\"a\":\"bad \uFFFD " + a.replacement(PIIEmail, "peggy@example.com") + "\"}"
	if string(got) != want {
		t.Errorf("changed string: got %q want %q", got, want)
	}

	truncatedRune := "[\"\xe2\x82"
	if got, res := streamJSON(t, a, truncatedRune, ""); !res.TextFallback || string(got) != truncatedRune {
		t.Errorf("truncated rune at EOF: fallback=%v got %q", res.TextFallback, got)
	}

	// Place a 3-byte rune, an escape, a surrogate pair and an email across
	// every offset relative to the 64 KiB buffer boundary.
	for shift := range 8 {
		pad := strings.Repeat("p", streamBufferSize-8+shift)
		body := `{"content":"` + pad + "€\\n\\ud83d\\ude00 quinn@example.com" + `"}`
		streamA, legacyA := newStreamTestAnonymizer(), newStreamTestAnonymizer()
		got, _ := streamJSON(t, streamA, body, "b")
		assertSameJSON(t, got, legacyAnonymizeJSON(legacyA, []byte(body), "b"))
		if !utf8.Valid(got) {
			t.Errorf("shift %d: output is not valid UTF-8", shift)
		}
	}
}

// failingReader returns data up to failAt bytes, then errInjected.
type failingReader struct {
	data   []byte
	failAt int
	pos    int
}

var errInjected = errors.New("injected I/O failure")

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= r.failAt {
		return 0, errInjected
	}
	n := copy(p[:min(len(p), r.failAt-r.pos)], r.data[r.pos:])
	r.pos += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// TestAnonymizeJSONStreamReadErrors injects a reader failure at every byte
// offset of representative documents (valid, and invalid ones that reach the
// text fallback) and requires the failure to be reported, never swallowed
// into a truncated "successful" body.
func TestAnonymizeJSONStreamReadErrors(t *testing.T) {
	docs := []string{
		streamCorpus["tool history"],
		streamCorpus["escapes and unicode"],
		streamCorpus["lone surrogates"],
		streamCorpus["big numbers"],
		"{\"a\":[true,false,null,-1.5e-3],\"b\":\"\xe2\x82\xac\"} ",
		`{"a":"\q victor@example.com"}`,
	}
	for _, doc := range docs {
		for failAt := range len(doc) {
			a := newStreamTestAnonymizer()
			r := &failingReader{data: []byte(doc), failAt: failAt}
			_, err := a.AnonymizeJSONStream(io.Discard, r, "s")
			if !errors.Is(err, errInjected) {
				t.Fatalf("doc %.30q fail at %d: err = %v, want injected read error", doc, failAt, err)
			}
			var re *readError
			if !errors.As(err, &re) || !strings.Contains(err.Error(), "read body") {
				t.Fatalf("doc %.30q fail at %d: error %v is not a read error", doc, failAt, err)
			}
		}
	}
}

// failingWriter accepts limit bytes, then fails every write.
type failingWriter struct {
	limit, n int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n+len(p) > w.limit {
		k := w.limit - w.n
		w.n = w.limit
		return k, errInjected
	}
	w.n += len(p)
	return len(p), nil
}

// countingReader counts bytes read from r.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestAnonymizeJSONStreamWriteErrors verifies output failures are reported
// for both the JSON rewrite and the text fallback, and that a failed write
// stops consumption of a large body instead of reading it to the end.
func TestAnonymizeJSONStreamWriteErrors(t *testing.T) {
	small := []string{streamCorpus["tool history"], "not json at all xavier@example.com"}
	for _, doc := range small {
		w := &failingWriter{limit: 0}
		_, err := newStreamTestAnonymizer().AnonymizeJSONStream(w, strings.NewReader(doc), "s")
		if !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "write body") {
			t.Errorf("doc %.30q: err = %v, want write error", doc, err)
		}
	}

	// 4 MiB of array elements; the writer fails after the first buffer flush.
	big := "[" + strings.Repeat(`"element",`, 400_000) + `"end"]`
	cr := &countingReader{r: strings.NewReader(big)}
	_, err := newStreamTestAnonymizer().AnonymizeJSONStream(&failingWriter{limit: 1}, cr, "s")
	if !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want write error", err)
	}
	if cr.n >= len(big) {
		t.Errorf("read all %d bytes after the output failed; want early stop", cr.n)
	}
}

// TestAnonymizeJSONStreamWriteErrorBeforeSyntaxError verifies a write failure
// is reported, without reading the rest of the body into the text fallback,
// when it precedes a syntax error.
func TestAnonymizeJSONStreamWriteErrorBeforeSyntaxError(t *testing.T) {
	body := "[" + strings.Repeat(`"element",`, 400_000) + `"end"] trailing ` + strings.Repeat("x", 1<<20)
	cr := &countingReader{r: strings.NewReader(body)}
	_, err := newStreamTestAnonymizer().AnonymizeJSONStream(&failingWriter{limit: 1}, cr, "s")
	if !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "write body") {
		t.Fatalf("err = %v, want write error", err)
	}
	if cr.n >= len(body) {
		t.Errorf("read the whole body (%d bytes) after the output failed", cr.n)
	}
}

// TestOffsetWriterRecordsErrors pins offsetWriter's error recording for each
// write method once the underlying writer has failed.
func TestOffsetWriterRecordsErrors(t *testing.T) {
	bw := bufio.NewWriterSize(&failingWriter{limit: 0}, 16)
	w := &offsetWriter{w: bw}
	w.write(bytes.Repeat([]byte("a"), 32)) // exceeds the buffer: forces a failing flush
	if !errors.Is(w.err, errInjected) {
		t.Fatalf("write: err = %v", w.err)
	}
	w.err = nil
	w.writeString(strings.Repeat("b", 32))
	if !errors.Is(w.err, errInjected) {
		t.Fatalf("writeString: err = %v", w.err)
	}
	w.err = nil
	w.writeByte('c')
	if !errors.Is(w.err, errInjected) {
		t.Fatalf("writeByte: err = %v", w.err)
	}
	if (&syntaxError{}).Error() != "anonymizer: invalid JSON" {
		t.Error("syntaxError message changed")
	}
}

// TestAnonymizeJSONStreamAllRuneEscapes covers every single-character escape.
func TestAnonymizeJSONStreamAllRuneEscapes(t *testing.T) {
	body := `{"content":"\" \\ \/ \b \f \n \r \t \u0001 \u00E9\u00e9 yvonne@example.com"}`
	streamA, legacyA := newStreamTestAnonymizer(), newStreamTestAnonymizer()
	got, _ := streamJSON(t, streamA, body, "e")
	assertSameJSON(t, got, legacyAnonymizeJSON(legacyA, []byte(body), "e"))
	if !strings.Contains(string(got), `\" \\ / \b \f \n \r \t \u0001 `) {
		t.Errorf("re-encoded escapes unexpected: %s", got)
	}
}

// FuzzAnonymizeJSONStream checks the streaming rewrite against the legacy
// implementation on arbitrary input: valid JSON without duplicate keys must
// decode identically and record the same tokens, every output must be valid
// JSON exactly when the input is, and the result must never panic.
func FuzzAnonymizeJSONStream(f *testing.F) {
	for _, body := range streamCorpus {
		f.Add([]byte(body))
	}
	f.Add([]byte(`not json zoe@example.com`))
	f.Add([]byte(`{"a":"\ud800\udc00","b":[1,2,{"c":null}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		streamA, legacyA := newStreamTestAnonymizer(), newStreamTestAnonymizer()
		got := streamA.AnonymizeJSON(body, "f")
		valid := json.Valid(body)
		if json.Valid(got) != valid && valid {
			t.Fatalf("valid input produced invalid output:\n in %q\nout %q", body, got)
		}
		if !valid || hasDuplicateKeys(body) {
			return
		}
		want := legacyAnonymizeJSON(legacyA, body, "f")
		var g, w any
		if err := json.Unmarshal(got, &g); err != nil {
			t.Fatalf("stream output invalid: %v", err)
		}
		if err := json.Unmarshal(want, &w); err != nil {
			t.Fatalf("legacy output invalid: %v", err)
		}
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("outputs differ for %q:\nstream %s\nlegacy %s", body, got, want)
		}
		if gs, ls := sessionMap(streamA, "f"), sessionMap(legacyA, "f"); !reflect.DeepEqual(gs, ls) {
			t.Fatalf("token maps differ for %q", body)
		}
	})
}

// hasDuplicateKeys reports whether any object in the valid JSON document
// repeats a member name.
func hasDuplicateKeys(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // next string token in this object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{obj: v == '{', keys: map[string]bool{}, key: true})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		case string:
			if top != nil && top.obj && top.key {
				if top.keys[v] {
					return true
				}
				top.keys[v] = true
				top.key = false
				continue
			}
		}
		if top != nil && top.obj {
			top.key = true
		}
	}
}

// ExampleAnonymizer_AnonymizeJSONStream shows the insertion contract.
func ExampleAnonymizer_AnonymizeJSONStream() {
	a := NewWithCacheAndCapacity(Options{EnabledPacks: []string{"GLOBAL"}})
	a.SetVerbose(false)
	a.SetPIIInstructions(map[string]string{"default": "Keep tokens."})
	var out bytes.Buffer
	res, _ := a.AnonymizeJSONStream(&out,
		strings.NewReader(`{"system":"Help.","messages":[{"role":"user","content":"x@example.com"}]}`), "id")
	body := out.String()
	off := res.Insertion.Offset
	fmt.Println(body[:off] + string(res.Insertion.Data) + body[off:])
	// Output: {"system":"Help.\n\nKeep tokens.","messages":[{"role":"user","content":"[PII_EMAIL_6d1db9ff40d653b4]"}]}
}

// TestRecordMappingDoesNotRetainInput pins that recording a token keeps only
// the matched value, not the string it was matched in. Before the fix the
// session map stored a substring, which kept every multi-megabyte request
// string containing PII reachable until the session was deleted, so live
// memory grew with the request instead of staying bounded.
func TestRecordMappingDoesNotRetainInput(t *testing.T) {
	a := NewWithCacheAndCapacity(Options{EnabledPacks: []string{"GLOBAL"}})
	a.SetVerbose(false)
	heapAfterGC := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	before := heapAfterGC()
	const size = 8 << 20
	func() {
		big := strings.Repeat("p", size) + " leak.check@example.com"
		if out := a.AnonymizeText(big, "retain"); strings.Contains(out, "leak.check@example.com") {
			t.Fatal("email not anonymized")
		}
	}()
	after := heapAfterGC()
	if after > before+size/4 {
		t.Errorf("heap grew by %d bytes while the session is alive; the %d-byte input is still reachable", after-before, size)
	}
	if got := sessionMap(a, "retain"); len(got) != 1 {
		t.Fatalf("session has %d tokens, want 1", len(got))
	}
	a.DeleteSession("retain")
}
