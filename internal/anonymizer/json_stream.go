package anonymizer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxJSONNestingDepth bounds container nesting in AnonymizeJSONStream. The
// rewriter is recursive, so the bound keeps adversarial input such as a body
// of '[' bytes from exhausting the goroutine stack. It equals encoding/json's
// own limit, so every document the former json.Unmarshal-based path accepted
// is still accepted, and deeper input is invalid for both.
const maxJSONNestingDepth = 10000

// streamBufferSize is the read and write buffer size of the streaming
// rewriter. Together with the largest single JSON string value (which must be
// held whole for regex detection) it bounds per-request processing memory.
const streamBufferSize = 64 << 10

// JSONInsertion is a byte sequence to splice into a rewritten body at Offset,
// a position in the output AnonymizeJSONStream wrote.
type JSONInsertion struct {
	Offset int64
	Data   []byte
}

// JSONStreamResult describes the output of AnonymizeJSONStream.
type JSONStreamResult struct {
	// BytesWritten is the number of bytes written to dst, excluding Insertion.
	BytesWritten int64
	// Insertion, when non-nil, is the PII system instruction that must be
	// spliced into the written bytes to complete the anonymized body.
	Insertion *JSONInsertion
}

// ErrInvalidJSON is returned by AnonymizeJSONStream when the input is not a
// single valid JSON value. By then dst may hold a rewritten prefix, which the
// caller must discard: the prefix was emitted before the input was known to
// be invalid, and anonymizing only what follows the syntax error would miss
// PII that spans it, so no text fallback is attempted here. Callers that hold
// the whole input use AnonymizeJSON, which anonymizes invalid input as text.
var ErrInvalidJSON = errors.New("anonymizer: request body is not valid JSON")

// TotalBytes returns the length of the complete anonymized body, including
// the insertion.
func (r JSONStreamResult) TotalBytes() int64 {
	if r.Insertion == nil {
		return r.BytesWritten
	}
	return r.BytesWritten + int64(len(r.Insertion.Data))
}

// AnonymizeJSONStream reads a request body from src, anonymizes it, and
// writes the result to dst without holding the whole document in memory.
//
// It applies the same rules as AnonymizeJSON: every JSON string value is
// passed through AnonymizeText, except values (and whole subtrees) under the
// structural keys model, temperature, max_tokens, top_p, stream and n; object
// keys, numbers, literals, whitespace and key order are preserved byte for
// byte, and string values that anonymization leaves unchanged are written
// with their original escaping. If any tokens were recorded for requestID and
// the top-level value is an object, the PII system instruction is returned as
// an Insertion rather than written, because whether it is needed is only known
// once the whole document has been read.
//
// Memory is bounded by the I/O buffers plus the largest single string value,
// which detection needs whole. Input consisting only of whitespace is copied
// unchanged. Any other input that is not a single valid JSON value makes it
// return ErrInvalidJSON, and the bytes written to dst must then be discarded.
//
// Otherwise the returned error is non-nil only when reading src or writing
// dst fails; it wraps the underlying error.
func (a *Anonymizer) AnonymizeJSONStream(dst io.Writer, src io.Reader, requestID string) (JSONStreamResult, error) {
	bw := bufio.NewWriterSize(dst, streamBufferSize)
	p := &jsonRewriter{
		a:  a,
		id: requestID,
		r:  bufio.NewReaderSize(src, streamBufferSize),
		w:  &offsetWriter{w: bw},
	}
	res, err := p.run()
	if err != nil {
		return JSONStreamResult{}, err
	}
	if err := bw.Flush(); err != nil {
		return JSONStreamResult{}, fmt.Errorf("anonymizer: write body: %w", err)
	}
	return res, nil
}

// skipKeys are structural request fields whose values are never anonymized.
var skipKeys = map[string]bool{
	"model": true, "temperature": true, "max_tokens": true,
	"top_p": true, "stream": true, "n": true,
}

// offsetWriter tracks how many bytes have been written so far, which gives
// the output offsets used for the PII-instruction insertion point. Write
// errors are sticky in bufio.Writer: after the first one every later write
// and the final Flush report it, so err only needs to hold the latest.
type offsetWriter struct {
	w   *bufio.Writer
	n   int64
	err error
}

func (o *offsetWriter) write(p []byte) {
	n, err := o.w.Write(p)
	o.n += int64(n)
	o.err = err
}

func (o *offsetWriter) writeString(s string) {
	n, err := o.w.WriteString(s)
	o.n += int64(n)
	o.err = err
}

func (o *offsetWriter) writeByte(c byte) {
	o.err = o.w.WriteByte(c)
	o.n++
}

// syntaxError reports that the input is not valid JSON at the current read
// position. run reports it to callers as ErrInvalidJSON.
type syntaxError struct{}

func (e *syntaxError) Error() string { return ErrInvalidJSON.Error() }

// readError wraps a failure of the underlying body reader.
type readError struct{ err error }

func (e *readError) Error() string { return "anonymizer: read body: " + e.err.Error() }
func (e *readError) Unwrap() error { return e.err }

// trackKind marks the containers whose members matter for injecting the PII
// system instruction.
type trackKind uint8

const (
	trackNone     trackKind = iota
	trackTop                // the top-level object
	trackMessages           // the top-level "messages" array
	trackMessage            // an element object of that array
)

// valueCtx carries the per-value processing mode down the recursion.
type valueCtx struct {
	anonymize bool // false inside a skipKeys subtree
	track     trackKind
}

// stringField records an emitted string value: its final text and the output
// offset of its closing quote.
type stringField struct {
	value string
	close int64
}

// valueInfo summarizes an emitted value for the injection decision.
type valueInfo struct {
	kind byte // '"', '[', '{', or 0 for numbers and literals
	str  stringField
	// Arrays: output offsets just after '[' and of ']', and element count.
	arrOpen, arrClose int64
	arrLen            int
	// trackMessages arrays: content of the first element with role "system".
	firstSystem *valueInfo
	hasSystem   bool
	// trackMessage objects: the last "role" and "content" members.
	role    *valueInfo
	content *valueInfo
}

// jsonRewriter is the recursive-descent rewriter behind AnonymizeJSONStream.
type jsonRewriter struct {
	a     *Anonymizer
	id    string
	r     *bufio.Reader
	w     *offsetWriter
	depth int

	// Top-level members relevant to injection; the last occurrence wins, as
	// with json.Unmarshal into a map.
	model    string
	system   *valueInfo
	messages *valueInfo
}

func (p *jsonRewriter) run() (JSONStreamResult, error) {
	res, err := p.document()
	if p.w.err != nil {
		// The output already failed; do not read the rest of the input.
		return JSONStreamResult{}, fmt.Errorf("anonymizer: write body: %w", p.w.err)
	}
	var se *syntaxError
	if errors.As(err, &se) {
		return JSONStreamResult{}, ErrInvalidJSON
	}
	// A write failure after the last value surfaces from the caller's Flush.
	return res, err
}

// document rewrites one top-level JSON value followed only by whitespace, or
// copies input that is only whitespace.
func (p *jsonRewriter) document() (JSONStreamResult, error) {
	first, err := p.peekNonWS()
	if errors.Is(err, errUnexpectedEOF) {
		return JSONStreamResult{BytesWritten: p.w.n}, nil // nothing to anonymize
	}
	if err != nil {
		return JSONStreamResult{}, err
	}
	ctx := valueCtx{anonymize: true}
	if first == '{' {
		ctx.track = trackTop
	}
	if _, err := p.value(ctx); err != nil {
		return JSONStreamResult{}, err
	}
	if _, err := p.peekNonWS(); !errors.Is(err, errUnexpectedEOF) {
		if err == nil {
			err = &syntaxError{} // trailing data after the top-level value
		}
		return JSONStreamResult{}, err
	}
	res := JSONStreamResult{BytesWritten: p.w.n}
	if first == '{' {
		res.Insertion = p.insertion()
	}
	return res, nil
}

// errUnexpectedEOF signals end of input where a value or delimiter is
// required. It is a syntaxError: such input is not valid JSON.
var errUnexpectedEOF = &syntaxError{}

// inputErr maps io.EOF to errUnexpectedEOF and other reader failures to
// readError.
func (p *jsonRewriter) inputErr(err error) error {
	if errors.Is(err, io.EOF) {
		return errUnexpectedEOF
	}
	return &readError{err: err}
}

// peekNonWS copies whitespace through and returns the next non-whitespace
// byte without consuming it.
func (p *jsonRewriter) peekNonWS() (byte, error) {
	for {
		buf, err := p.r.Peek(1)
		if err != nil {
			return 0, p.inputErr(err)
		}
		switch c := buf[0]; c {
		case ' ', '\t', '\n', '\r':
			p.w.writeByte(c)
			_, _ = p.r.Discard(1) // the byte is buffered; Discard cannot fail
		default:
			return c, nil
		}
	}
}

// expect consumes the next non-whitespace byte, which must be c, and writes it.
func (p *jsonRewriter) expect(c byte) error {
	got, err := p.peekNonWS()
	if err != nil {
		return err
	}
	if got != c {
		return &syntaxError{}
	}
	p.consume(c)
	return nil
}

// consume discards the already-peeked byte c and writes it.
func (p *jsonRewriter) consume(c byte) {
	_, _ = p.r.Discard(1)
	p.w.writeByte(c)
}

func (p *jsonRewriter) value(ctx valueCtx) (valueInfo, error) {
	if p.w.err != nil {
		// Stop consuming input once the output can no longer be written.
		return valueInfo{}, fmt.Errorf("anonymizer: write body: %w", p.w.err)
	}
	c, err := p.peekNonWS()
	if err != nil {
		return valueInfo{}, err
	}
	switch {
	case c == '{':
		return p.object(ctx)
	case c == '[':
		return p.array(ctx)
	case c == '"':
		return p.stringValue(ctx)
	case c == '-' || (c >= '0' && c <= '9'):
		return valueInfo{}, p.number()
	case c == 't':
		return valueInfo{}, p.literal("true")
	case c == 'f':
		return valueInfo{}, p.literal("false")
	case c == 'n':
		return valueInfo{}, p.literal("null")
	}
	return valueInfo{}, &syntaxError{}
}

func (p *jsonRewriter) enter() error {
	if p.depth >= maxJSONNestingDepth {
		return &syntaxError{}
	}
	p.depth++
	return nil
}

func (p *jsonRewriter) object(ctx valueCtx) (valueInfo, error) {
	if err := p.enter(); err != nil {
		return valueInfo{}, err
	}
	defer func() { p.depth-- }()
	info := valueInfo{kind: '{'}
	p.consume('{') // peeked by value
	c, err := p.peekNonWS()
	if err != nil {
		return info, err
	}
	if c == '}' {
		return info, p.expect('}')
	}
	for {
		if c, err = p.peekNonWS(); err != nil {
			return info, err
		}
		if c != '"' {
			return info, &syntaxError{}
		}
		key, raw, err := p.scanString(true)
		if err != nil {
			return info, err
		}
		p.w.write(raw)
		if err = p.expect(':'); err != nil {
			return info, err
		}
		child := valueCtx{anonymize: ctx.anonymize && !skipKeys[key]}
		if ctx.track == trackTop && key == "messages" {
			child.track = trackMessages
		}
		v, err := p.value(child)
		if err != nil {
			return info, err
		}
		p.recordMember(ctx.track, key, v, &info)

		if c, err = p.peekNonWS(); err != nil {
			return info, err
		}
		switch c {
		case ',':
			_ = p.expect(',') // peeked above
		case '}':
			return info, p.expect('}')
		default:
			return info, &syntaxError{}
		}
	}
}

// recordMember keeps the members that decide where the PII instruction goes.
func (p *jsonRewriter) recordMember(track trackKind, key string, v valueInfo, obj *valueInfo) {
	switch track {
	case trackTop:
		switch key {
		case "model":
			p.model = v.str.value // "" unless the value is a string
		case "system":
			p.system = &v
		case "messages":
			p.messages = &v
		}
	case trackMessage:
		switch key {
		case "role":
			obj.role = &v
		case "content":
			obj.content = &v
		}
	}
}

func (p *jsonRewriter) array(ctx valueCtx) (valueInfo, error) {
	if err := p.enter(); err != nil {
		return valueInfo{}, err
	}
	defer func() { p.depth-- }()
	info := valueInfo{kind: '['}
	p.consume('[') // peeked by value
	info.arrOpen = p.w.n
	elem := valueCtx{anonymize: ctx.anonymize}
	if ctx.track == trackMessages {
		elem.track = trackMessage
	}
	c, err := p.peekNonWS()
	if err != nil {
		return info, err
	}
	if c == ']' {
		info.arrClose = p.w.n
		return info, p.expect(']')
	}
	for {
		v, err := p.value(elem)
		if err != nil {
			return info, err
		}
		info.arrLen++
		if ctx.track == trackMessages && !info.hasSystem && v.kind == '{' &&
			v.role != nil && v.role.kind == '"' && v.role.str.value == "system" {
			info.hasSystem = true
			info.firstSystem = v.content
		}
		if c, err = p.peekNonWS(); err != nil {
			return info, err
		}
		switch c {
		case ',':
			_ = p.expect(',') // peeked above
		case ']':
			info.arrClose = p.w.n
			return info, p.expect(']')
		default:
			return info, &syntaxError{}
		}
	}
}

// stringValue rewrites a string value, anonymizing it unless ctx is a
// skipped subtree.
func (p *jsonRewriter) stringValue(ctx valueCtx) (valueInfo, error) {
	s, raw, err := p.scanString(!ctx.anonymize)
	if err != nil {
		return valueInfo{}, err
	}
	info := valueInfo{kind: '"'}
	out := s
	if ctx.anonymize {
		out = p.a.AnonymizeText(s, p.id)
	}
	if out == s && raw != nil {
		// Unchanged: keep the client's original escaping.
		p.w.write(raw[:len(raw)-1])
	} else {
		p.w.writeByte('"')
		writeJSONStringContent(p.w, out)
	}
	info.str = stringField{value: out, close: p.w.n}
	p.w.writeByte('"')
	return info, nil
}

// scanString consumes a JSON string token and returns its decoded value. It
// also returns the raw token bytes (quotes included) when keepRaw is set or
// when the raw form differs from the decoded one (escapes or invalid UTF-8);
// otherwise raw is nil and the token is exactly '"' + value + '"'.
//
// Decoding matches encoding/json: escapes are resolved, an unpaired UTF-16
// surrogate becomes U+FFFD, and so does each byte of invalid UTF-8, so the
// detection input is identical to what json.Unmarshal produced.
func (p *jsonRewriter) scanString(keepRaw bool) (string, []byte, error) {
	var b strings.Builder
	var raw []byte
	activateRaw := func() {
		if raw == nil {
			raw = make([]byte, 0, b.Len()+16)
			raw = append(raw, '"')
			raw = append(raw, b.String()...)
		}
	}
	if keepRaw {
		activateRaw()
	}
	_, _ = p.r.Discard(1) // opening quote, peeked by the caller
	for {
		buf, err := p.r.Peek(1)
		if err != nil {
			return "", nil, p.tokenErr(err)
		}
		if n := p.r.Buffered(); n > 1 {
			buf, _ = p.r.Peek(n) // all buffered bytes; cannot fail
		}
		i := 0
		for i < len(buf) {
			if c := buf[i]; c == '"' || c == '\\' || c < 0x20 || c >= utf8.RuneSelf {
				break
			}
			i++
		}
		if i > 0 {
			b.Write(buf[:i])
			if raw != nil {
				raw = append(raw, buf[:i]...)
			}
			_, _ = p.r.Discard(i)
			continue
		}
		switch c := buf[0]; {
		case c == '"':
			_, _ = p.r.Discard(1)
			if raw != nil {
				raw = append(raw, '"')
			}
			return b.String(), raw, nil
		case c == '\\':
			activateRaw()
			if err := p.escape(&b, &raw); err != nil {
				return "", nil, err
			}
		case c < 0x20:
			return "", nil, &syntaxError{}
		default:
			if err := p.utf8Rune(&b, &raw, activateRaw); err != nil {
				return "", nil, err
			}
		}
	}
}

// tokenErr converts an input error inside a token: end of input is a syntax
// error, anything else a read failure.
func (p *jsonRewriter) tokenErr(err error) error {
	if errors.Is(err, io.EOF) {
		return &syntaxError{}
	}
	return &readError{err: err}
}

// utf8Rune decodes one multi-byte UTF-8 sequence (or invalid byte) at the
// read position into b, replacing invalid bytes with U+FFFD.
func (p *jsonRewriter) utf8Rune(b *strings.Builder, raw *[]byte, activateRaw func()) error {
	buf, err := p.r.Peek(utf8.UTFMax)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return &readError{err: err}
	}
	r, size := utf8.DecodeRune(buf)
	if r == utf8.RuneError && size == 1 {
		activateRaw()
	}
	b.WriteRune(r)
	if *raw != nil {
		*raw = append(*raw, buf[:size]...)
	}
	_, _ = p.r.Discard(size)
	return nil
}

// escape decodes one backslash escape at the read position into b and
// appends its raw bytes to raw (which is active whenever escapes are seen).
func (p *jsonRewriter) escape(b *strings.Builder, raw *[]byte) error {
	esc, err := p.r.Peek(2)
	if err != nil {
		*raw = append(*raw, esc...)
		_, _ = p.r.Discard(len(esc))
		return p.tokenErr(err)
	}
	var decoded byte
	switch esc[1] {
	case '"', '\\', '/':
		decoded = esc[1]
	case 'b':
		decoded = '\b'
	case 'f':
		decoded = '\f'
	case 'n':
		decoded = '\n'
	case 'r':
		decoded = '\r'
	case 't':
		decoded = '\t'
	case 'u':
		return p.unicodeEscape(b, raw)
	default:
		return &syntaxError{}
	}
	b.WriteByte(decoded)
	*raw = append(*raw, esc...)
	_, _ = p.r.Discard(2)
	return nil
}

// unicodeEscape decodes \uXXXX, combining a valid surrogate pair and
// replacing an unpaired surrogate with U+FFFD as encoding/json does.
func (p *jsonRewriter) unicodeEscape(b *strings.Builder, raw *[]byte) error {
	r, ok, err := p.hex4(raw)
	if err != nil || !ok {
		return err
	}
	if utf16.IsSurrogate(r) {
		// A following \uXXXX may complete the pair; peek without consuming.
		next, err := p.r.Peek(6)
		if err != nil && !errors.Is(err, io.EOF) {
			return &readError{err: err}
		}
		if err == nil && next[0] == '\\' && next[1] == 'u' {
			if r2, ok := parseHex4(next[2:]); ok {
				if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
					*raw = append(*raw, next...)
					_, _ = p.r.Discard(6)
					b.WriteRune(dec)
					return nil
				}
			}
		}
		r = utf8.RuneError
	}
	b.WriteRune(r)
	return nil
}

// hex4 consumes "\uXXXX" at the read position and returns the code unit.
// ok is false, with err set, when the escape is malformed or truncated.
func (p *jsonRewriter) hex4(raw *[]byte) (rune, bool, error) {
	esc, err := p.r.Peek(6)
	if err != nil {
		*raw = append(*raw, esc...)
		_, _ = p.r.Discard(len(esc))
		return 0, false, p.tokenErr(err)
	}
	r, ok := parseHex4(esc[2:])
	if !ok {
		return 0, false, &syntaxError{}
	}
	*raw = append(*raw, esc...)
	_, _ = p.r.Discard(6)
	return r, true, nil
}

func parseHex4(h []byte) (rune, bool) {
	var r rune
	for _, c := range h[:4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// number copies a JSON number token, validating its grammar
// (-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?).
func (p *jsonRewriter) number() error {
	var tok []byte
	// next peeks the byte after the token so far; ok is false at EOF.
	next := func() (c byte, ok bool, err error) {
		buf, err := p.r.Peek(1)
		if errors.Is(err, io.EOF) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, &readError{err: err}
		}
		return buf[0], true, nil
	}
	take := func(c byte) {
		_, _ = p.r.Discard(1) // peeked by next
		tok = append(tok, c)
	}
	// digits consumes a run of digits and returns its length and the peeked
	// byte that ended it.
	digits := func() (n int, c byte, ok bool, err error) {
		for {
			if c, ok, err = next(); err != nil || !ok || c < '0' || c > '9' {
				return n, c, ok, err
			}
			take(c)
			n++
		}
	}
	fail := func() error { return &syntaxError{} }

	c, ok, _ := next() // value peeked a byte, so this cannot fail
	var err error
	if c == '-' {
		take(c)
		if c, ok, err = next(); err != nil {
			return err
		}
	}
	switch {
	case ok && c == '0':
		take(c)
		c, ok, err = next()
	case ok && c >= '1' && c <= '9':
		_, c, ok, err = digits()
	default:
		return fail()
	}
	if err != nil {
		return err
	}
	if ok && c == '.' {
		take(c)
		var n int
		if n, c, ok, err = digits(); err != nil {
			return err
		}
		if n == 0 {
			return fail()
		}
	}
	if ok && (c == 'e' || c == 'E') {
		take(c)
		if c, ok, err = next(); err != nil {
			return err
		}
		if ok && (c == '+' || c == '-') {
			take(c)
		}
		n, _, _, err := digits()
		if err != nil {
			return err
		}
		if n == 0 {
			return fail()
		}
	}
	p.w.write(tok)
	return nil
}

// literal copies one of the literals true, false or null.
func (p *jsonRewriter) literal(lit string) error {
	buf, err := p.r.Peek(len(lit))
	if string(buf) == lit {
		_, _ = p.r.Discard(len(lit))
		p.w.writeString(lit)
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return &readError{err: err}
	}
	return &syntaxError{}
}

// insertion decides, after the whole top-level object has been written,
// whether and where the PII system instruction goes. It mirrors
// injectPIIInstruction: a string "system" gets the instruction appended, a
// "system" array gets a text block appended, and otherwise the first
// "messages" element with role "system" gets it appended to a string
// content, or a new system message is prepended.
func (p *jsonRewriter) insertion() *JSONInsertion {
	if p.id == "" || p.a.SessionTokenCount(p.id) == 0 {
		return nil
	}
	instruction := p.a.resolvePIIInstruction(p.model)
	if instruction == "" {
		return nil
	}
	if sys := p.system; sys != nil {
		switch sys.kind {
		case '"':
			return appendToString(sys.str, instruction)
		case '[':
			var data strings.Builder
			if sys.arrLen > 0 {
				data.WriteByte(',')
			}
			data.WriteString(`{"type":"text","text":"`)
			writeJSONStringContentTo(&data, instruction)
			data.WriteString(`"}`)
			return &JSONInsertion{Offset: sys.arrClose, Data: []byte(data.String())}
		}
	}
	msgs := p.messages
	if msgs == nil || msgs.kind != '[' {
		return nil
	}
	if msgs.hasSystem {
		if c := msgs.firstSystem; c != nil && c.kind == '"' {
			return appendToString(c.str, instruction)
		}
		return nil
	}
	var data strings.Builder
	data.WriteString(`{"role":"system","content":"`)
	writeJSONStringContentTo(&data, instruction)
	data.WriteString(`"}`)
	if msgs.arrLen > 0 {
		data.WriteByte(',')
	}
	return &JSONInsertion{Offset: msgs.arrOpen, Data: []byte(data.String())}
}

// appendToString returns the insertion that appends instruction to an
// emitted string value, separated by a blank line unless the value is empty.
func appendToString(f stringField, instruction string) *JSONInsertion {
	text := instruction
	if f.value != "" {
		text = "\n\n" + instruction
	}
	var data strings.Builder
	writeJSONStringContentTo(&data, text)
	return &JSONInsertion{Offset: f.close, Data: []byte(data.String())}
}

// writeJSONStringContent writes s as the inside of a JSON string literal.
// Only '"', '\\' and control characters are escaped; all other bytes,
// including non-ASCII UTF-8, are written as is.
func writeJSONStringContent(w *offsetWriter, s string) {
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '"' && c != '\\' && c >= 0x20 {
			continue
		}
		w.writeString(s[start:i])
		w.writeString(jsonEscape(c))
		start = i + 1
	}
	w.writeString(s[start:])
}

// writeJSONStringContentTo is writeJSONStringContent for a strings.Builder.
func writeJSONStringContentTo(b *strings.Builder, s string) {
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '"' && c != '\\' && c >= 0x20 {
			continue
		}
		b.WriteString(s[start:i])
		b.WriteString(jsonEscape(c))
		start = i + 1
	}
	b.WriteString(s[start:])
}

// jsonEscape returns the escape sequence for a byte that must be escaped
// inside a JSON string.
func jsonEscape(c byte) string {
	switch c {
	case '"':
		return `\"`
	case '\\':
		return `\\`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	}
	const hex = "0123456789abcdef"
	return `\u00` + string([]byte{hex[c>>4], hex[c&0xf]})
}
