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
			got, _ := streamJSON(t, streamA, body, "sess")
			want := legacyAnonymizeJSON(legacyA, []byte(body), "sess")
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
	if res.Insertion != nil {
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

// streamErr runs AnonymizeJSONStream on body and returns only its error.
func streamErr(a *Anonymizer, body, id string) error {
	_, err := a.AnonymizeJSONStream(io.Discard, strings.NewReader(body), id)
	return err
}

// invalidJSONCases are inputs that are not a single valid JSON value. The
// first four are the review reproductions of PII that a remainder-only text
// fallback leaked: the parser had already emitted a prefix ("123", "true",
// a skip-key value, an object key) before the syntax error, so anonymizing
// only what followed missed the address. All personal data is synthetic.
var invalidJSONCases = map[string]string{
	"number before address":     `123@example.com`,
	"literal before address":    `true@example.com`,
	"address in skip-key value": `{"model":"alice@example.com",}`,
	"address in object key":     `{"alice@example.com":0,}`,
	"not json":                  "not json victor@example.com",
	"binary":                    "\x1f\x8b\x08victor@example.com",
	"trailing data":             `{"a":"victor@example.com"} {"b":"victor@example.com"}`,
	"truncated string":          `{"a":"victor@example.com`,
	"truncated object":          `{"a":"victor@example.com",`,
	"control char in string":    "{\"a\":\"x\x01victor@example.com\"}",
	"bad escape":                `{"a":"\q victor@example.com"}`,
	"truncated escape":          `{"a":"\`,
	"truncated unicode escape":  `{"a":"\u00`,
	"bad unicode escape":        `{"a":"\u00zz victor@example.com"}`,
	"missing colon":             `{"a" "victor@example.com"}`,
	"missing comma":             `{"a":1 "b":"victor@example.com"}`,
	"trailing comma":            `{"a":1,}`,
	"unquoted key":              `{a:1}`,
	"array missing comma":       `["a" "victor@example.com"]`,
	"bad literal":               `{"a":tru}`,
	"truncated literal":         `[nul`,
	"bad value start":           `{"a":+1}`,
	"minus only":                `[-]`,
	"leading zero":              `[01]`,
	"bare fraction":             `[1.]`,
	"bare exponent":             `[1e]`,
	"truncated number":          `[1.`,
	"unterminated array":        `["victor@example.com"`,
}

// TestAnonymizeJSONStreamRejectsInvalidJSON pins that the stream never emits
// a partial rewrite as if it were complete: every input that is not a single
// valid JSON value is reported as ErrInvalidJSON. AnonymizeJSON, which holds
// the whole input, anonymizes such input exactly as the pre-streaming
// implementation did (AnonymizeText of the whole body), so no synthetic
// address survives and the token map matches.
func TestAnonymizeJSONStreamRejectsInvalidJSON(t *testing.T) {
	for name, in := range invalidJSONCases {
		t.Run(name, func(t *testing.T) {
			a, legacyA := newStreamTestAnonymizer(), newStreamTestAnonymizer()
			if err := streamErr(a, in, "sess-inv"); !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("stream error = %v, want ErrInvalidJSON", err)
			}
			got := string(a.AnonymizeJSON([]byte(in), "sess-inv"))
			want := string(legacyAnonymizeJSON(legacyA, []byte(in), "sess-inv"))
			if got != want {
				t.Errorf("AnonymizeJSON differs from the legacy whole-body text path:\n got %q\nwant %q", got, want)
			}
			if strings.Contains(got, "@example.com") {
				t.Errorf("raw synthetic address survived: %q", got)
			}
			if gs, ls := sessionMap(a, "sess-inv"), sessionMap(legacyA, "sess-inv"); !reflect.DeepEqual(gs, ls) {
				t.Errorf("token maps differ:\n got %v\nwant %v", gs, ls)
			}
		})
	}
}

// TestAnonymizeJSONStreamWhitespaceOnly pins that empty and whitespace-only
// bodies, which hold no PII, are copied unchanged rather than rejected.
func TestAnonymizeJSONStreamWhitespaceOnly(t *testing.T) {
	a := newStreamTestAnonymizer()
	for _, in := range []string{"", " \n\t\r"} {
		got, res := streamJSON(t, a, in, "")
		if string(got) != in || res.Insertion != nil {
			t.Errorf("whitespace-only input %q: got %q, insertion %v", in, got, res.Insertion)
		}
	}
}

// TestAnonymizeJSONStreamNestingLimit verifies documents at the nesting limit
// are rewritten as JSON and deeper ones are rejected without recursion past
// the limit, as json.Valid rejects them.
func TestAnonymizeJSONStreamNestingLimit(t *testing.T) {
	a := newStreamTestAnonymizer()
	atLimit := strings.Repeat("[", maxJSONNestingDepth) + `"x"` + strings.Repeat("]", maxJSONNestingDepth)
	if got, _ := streamJSON(t, a, atLimit, ""); string(got) != atLimit {
		t.Error("document at the nesting limit changed")
	}

	tooDeep := strings.Repeat("[", maxJSONNestingDepth+1) + strings.Repeat("]", maxJSONNestingDepth+1)
	tooDeepObj := strings.Repeat(`{"a":`, maxJSONNestingDepth+1)
	for name, in := range map[string]string{"arrays": tooDeep, "objects": tooDeepObj} {
		if json.Valid([]byte(in)) {
			t.Fatalf("%s past the nesting limit are valid for encoding/json", name)
		}
		if err := streamErr(a, in, ""); !errors.Is(err, ErrInvalidJSON) {
			t.Errorf("%s past the nesting limit: stream error = %v, want ErrInvalidJSON", name, err)
		}
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
	if err := streamErr(a, truncatedRune, ""); !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("truncated rune at EOF: stream error = %v, want ErrInvalidJSON", err)
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
// offset of representative documents and requires the failure to be
// reported, never swallowed into a truncated "successful" body. For an
// invalid document, a failure before the syntax error is a read error, and
// the stream reads nothing past the error, so a later failure is never
// reached and the result is ErrInvalidJSON.
func TestAnonymizeJSONStreamReadErrors(t *testing.T) {
	invalid := `{"a":"\q victor@example.com"}`
	syntaxAt := strings.Index(invalid, "q") // the stream reads up to the bad escape byte
	for failAt := range len(invalid) {
		_, err := newStreamTestAnonymizer().AnonymizeJSONStream(io.Discard, &failingReader{data: []byte(invalid), failAt: failAt}, "s")
		want := errInjected
		if failAt > syntaxAt {
			want = ErrInvalidJSON
		}
		if !errors.Is(err, want) {
			t.Fatalf("invalid doc fail at %d: err = %v, want %v", failAt, err, want)
		}
	}

	docs := []string{
		streamCorpus["tool history"],
		streamCorpus["escapes and unicode"],
		streamCorpus["lone surrogates"],
		streamCorpus["big numbers"],
		"{\"a\":[true,false,null,-1.5e-3],\"b\":\"\xe2\x82\xac\"} ",
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
// for both a JSON rewrite and a copied whitespace-only body, and that a
// failed write stops consumption of a large body instead of reading it to
// the end.
func TestAnonymizeJSONStreamWriteErrors(t *testing.T) {
	small := []string{streamCorpus["tool history"], " \n\t "}
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
// that precedes a syntax error is reported as such, without reading on to
// the syntax error.
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
	if (&syntaxError{}).Error() != ErrInvalidJSON.Error() {
		t.Error("syntaxError message differs from ErrInvalidJSON")
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
	for _, body := range invalidJSONCases {
		f.Add([]byte(body))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		streamA, legacyA := newStreamTestAnonymizer(), newStreamTestAnonymizer()
		valid := json.Valid(body)
		// The stream accepts exactly what json.Valid accepts, plus
		// whitespace-only input, which it copies.
		blank := len(bytes.TrimLeft(body, " \t\r\n")) == 0
		if err := streamErr(newStreamTestAnonymizer(), string(body), "f"); (err == nil) != (valid || blank) {
			t.Fatalf("stream error %v disagrees with json.Valid=%v for %q", err, valid, body)
		}
		got := streamA.AnonymizeJSON(body, "f")
		if !valid {
			// Invalid input must be anonymized exactly as the legacy
			// whole-body text path did, never as a partial rewrite.
			if want := legacyAnonymizeJSON(legacyA, body, "f"); !bytes.Equal(got, want) {
				t.Fatalf("invalid input differs from legacy for %q:\nstream %q\nlegacy %q", body, got, want)
			}
			if gs, ls := sessionMap(streamA, "f"), sessionMap(legacyA, "f"); !reflect.DeepEqual(gs, ls) {
				t.Fatalf("token maps differ for invalid %q", body)
			}
			return
		}
		if !json.Valid(got) {
			t.Fatalf("valid input produced invalid output:\n in %q\nout %q", body, got)
		}
		if hasDuplicateKeys(body) {
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
