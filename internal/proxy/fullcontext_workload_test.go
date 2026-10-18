package proxy

import (
	"bufio"
	"bytes"
	"crypto/md5" // #nosec G501 -- recomputes the anonymizer's deterministic token format, not for security
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// detStream is a reproducible byte stream (SHA-256 in counter mode) for
// synthetic workload data. Determinism is the point; it is not a source of
// secrets or randomness.
type detStream struct {
	seed    uint64
	counter uint64
	block   [sha256.Size]byte
	pos     int
}

func newDetStream(seed uint64) *detStream {
	return &detStream{seed: seed, pos: sha256.Size}
}

func (d *detStream) byte() byte {
	if d.pos == sha256.Size {
		var in [16]byte
		binary.BigEndian.PutUint64(in[:8], d.seed)
		binary.BigEndian.PutUint64(in[8:], d.counter)
		d.counter++
		d.block = sha256.Sum256(in[:])
		d.pos = 0
	}
	b := d.block[d.pos]
	d.pos++
	return b
}

func (d *detStream) fill(p []byte) {
	for i := range p {
		p[i] = d.byte()
	}
}

// fullContextWorkload generates a synthetic OpenAI-style chat request of the
// kind that fills a large context window: a system prompt, long user turns of
// prose carrying synthetic email addresses, assistant tool calls whose JSON
// arguments carry the same addresses, tool results echoing them, and inline
// base64 image inputs. All personal data is synthetic (*.synthetic@example.com).
//
// generate writes the raw request and, independently, the exact body the
// proxy must forward: every address replaced by its [PII_EMAIL_<md5[:16]>]
// token and the PII instruction appended to the system prompt. Expected
// bytes are derived from the token format, not from the anonymizer, so the
// comparison is an independent oracle.
type fullContextWorkload struct {
	turns       int // user/assistant/tool exchanges
	proseBytes  int // approximate prose bytes per user turn
	images      int // inline images, attached to the first turns
	imageBytes  int // decoded bytes per image
	instruction string
}

const fullContextSystemPrompt = "You are a support assistant. Answer using the account history below."

// proseWords contains no word that any GLOBAL pattern keys on (no "token",
// "secret", "bearer", "api key", digits runs or '@').
var proseWords = strings.Fields("the customer asked about invoices shipping plans upgrade " +
	"renewal support ticket history refund policy delivery window account settings " +
	"team members billing cycle usage report notes follow up escalation agreed " +
	"schedule meeting summary priority status pending resolved quality feedback")

// emailToken reproduces the anonymizer's token for a synthetic email address.
func emailToken(email string) string {
	sum := md5.Sum([]byte(email)) // #nosec G401 -- token format reproduction, not security
	return "[PII_EMAIL_" + hex.EncodeToString(sum[:])[:16] + "]"
}

func syntheticEmail(turn, k int) string {
	return fmt.Sprintf("user%d.%d.synthetic@example.com", turn, k)
}

// dualWriter writes the raw request and the expected anonymized body.
type dualWriter struct {
	raw, exp *bufio.Writer
}

func (d dualWriter) same(s string) {
	_, _ = d.raw.WriteString(s)
	_, _ = d.exp.WriteString(s)
}

func (d dualWriter) email(e string) {
	_, _ = d.raw.WriteString(e)
	_, _ = d.exp.WriteString(emailToken(e))
}

// generate writes the workload; see the type documentation.
func (w fullContextWorkload) generate(raw, expected io.Writer) error {
	d := dualWriter{raw: bufio.NewWriterSize(raw, 64<<10), exp: bufio.NewWriterSize(expected, 64<<10)}
	rng := newDetStream(152)

	d.same(`{"model":"gpt-x","messages":[{"role":"system","content":"` + fullContextSystemPrompt)
	_, _ = d.exp.WriteString(`\n\n` + w.instruction) // instruction is plain ASCII: no escaping needed
	d.same(`"}`)

	for turn := range w.turns {
		d.same(`,{"role":"user","content":[{"type":"text","text":"`)
		written := 0
		for k := 0; written < w.proseBytes; k++ {
			for range 300 {
				word := proseWords[int(rng.byte())%len(proseWords)]
				d.same(word + " ")
				written += len(word) + 1
			}
			d.same(`contact `)
			d.email(syntheticEmail(turn, k%4))
			d.same(` \n`)
		}
		d.same(`"}`)
		if turn < w.images {
			d.same(`,{"type":"image_url","image_url":{"url":"data:image/png;base64,`)
			img := make([]byte, w.imageBytes)
			rng.fill(img)
			d.same(base64.StdEncoding.EncodeToString(img))
			d.same(`"}}`)
		}
		d.same(`]}`)

		email := syntheticEmail(turn, 0)
		d.same(fmt.Sprintf(`,{"role":"assistant","content":null,"tool_calls":[{"id":"call_%d","type":"function","function":{"name":"crm_lookup","arguments":"{\"email\":\"`, turn))
		d.email(email)
		d.same(`\",\"fields\":[\"plan\",\"history\"]}"}}]}`)
		d.same(fmt.Sprintf(`,{"role":"tool","tool_call_id":"call_%d","content":"{\"customer\":\"`, turn))
		d.email(email)
		d.same(`\",\"plan\":\"pro\",\"history\":\"renewal agreed\\nrefund resolved\"}"}`)
	}
	d.same(`],"tools":[{"type":"function","function":{"name":"crm_lookup","description":"Look up an account",` +
		`"parameters":{"type":"object","properties":{"email":{"type":"string"},"fields":{"type":"array","items":{"type":"string"}}}}}}],` +
		`"temperature":0.2,"stream":false}`)
	if err := d.raw.Flush(); err != nil {
		return err
	}
	return d.exp.Flush()
}

// workloadDigest summarizes a byte stream by length and SHA-256.
type workloadDigest struct {
	n   int64
	sum [32]byte
}

type digestWriter struct {
	h hash.Hash
	n int64
}

func newDigestWriter() *digestWriter { return &digestWriter{h: sha256.New()} }

func (d *digestWriter) Write(p []byte) (int, error) {
	d.n += int64(len(p))
	return d.h.Write(p)
}

func (d *digestWriter) digest() workloadDigest {
	var out workloadDigest
	out.n = d.n
	copy(out.sum[:], d.h.Sum(nil))
	return out
}

// digests returns the raw and expected digests without materializing either.
func (w fullContextWorkload) digests() (raw, expected workloadDigest, err error) {
	r, e := newDigestWriter(), newDigestWriter()
	if err := w.generate(r, e); err != nil {
		return raw, expected, err
	}
	return r.digest(), e.digest(), nil
}

// rawStream streams the raw request through a pipe.
func (w fullContextWorkload) rawStream() io.ReadCloser {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(w.generate(pw, io.Discard)) }()
	return pr
}

// upstreamCheck consumes a forwarded body, recording its digest and whether
// any raw synthetic address or address fragment reached the upstream.
type upstreamCheck struct {
	digest        workloadDigest
	contentLength int64
	leaked        bool
}

// leakMarker is part of every synthetic address and of no token.
var leakMarker = []byte(".synthetic@example.com")

func checkUpstreamBody(body io.Reader, contentLength int64) (upstreamCheck, error) {
	dw := newDigestWriter()
	res := upstreamCheck{contentLength: contentLength}
	buf := make([]byte, 256<<10)
	var tail []byte
	for {
		n, err := body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = dw.Write(chunk)
			window := append(tail, chunk...)
			if bytes.Contains(window, leakMarker) {
				res.leaked = true
			}
			keep := min(len(window), len(leakMarker)-1)
			tail = append([]byte{}, window[len(window)-keep:]...)
		}
		if err == io.EOF {
			res.digest = dw.digest()
			return res, nil
		}
		if err != nil {
			return res, err
		}
	}
}
