package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Request content-coding support (issue #153).
//
// Clients may compress request bodies (OpenCode, for example, sends
// "Content-Encoding: zstd"). The anonymizer only understands decoded content,
// so the body is decoded, validated, anonymized and then re-encoded with the
// same coding chain before it is forwarded. Bodies whose coding is unsupported
// or malformed are rejected: forwarding them would bypass anonymization, and
// running the text anonymizer over compressed bytes corrupts the stream.

// acceptedRequestEncodings is advertised in the Accept-Encoding header of a 415
// response (RFC 9110 §12.5.3).
const acceptedRequestEncodings = "gzip, deflate, zstd"

// zstdMaxWindow is the largest zstd window accepted and produced. RFC 9659
// makes 8 MB the interoperable window limit for the "zstd" HTTP content
// coding; it bounds decoder memory independently of the body size.
const zstdMaxWindow = 8 << 20

// zstdDecoderOptions configures request-body zstd decoding: synchronous
// decoding (no background goroutines per request), low-memory buffers and the
// RFC 9659 window bound. Single-segment frames, whose window equals their
// content size, are not affected by the window bound. Package var so tests can
// exercise decoder-construction failure.
var zstdDecoderOptions = []zstd.DOption{
	zstd.WithDecoderConcurrency(1),
	zstd.WithDecoderLowmem(true),
	zstd.WithDecoderMaxWindow(zstdMaxWindow),
}

// zstdEncoderOptions configures re-encoding of the anonymized body with a
// single goroutine and a window within the RFC 9659 bound. Package var so tests
// can exercise encoder-construction failure.
var zstdEncoderOptions = []zstd.EOption{
	zstd.WithEncoderConcurrency(1),
	zstd.WithWindowSize(zstdMaxWindow),
}

// requestBodyError rejects a request body with a specific client-facing status.
// msg is the generic text sent to the client; err carries the detail for logs.
type requestBodyError struct {
	status int
	msg    string
	err    error
}

func (e *requestBodyError) Error() string { return e.msg + ": " + e.err.Error() }
func (e *requestBodyError) Unwrap() error { return e.err }

func badRequestBody(err error) error {
	return &requestBodyError{status: http.StatusBadRequest, msg: "malformed request body", err: err}
}

// writeRequestBodyError sends the client response for a failed
// anonymizeRequestBody. Errors without a specific status keep the historical
// 413 response (body too large, client read failure).
func writeRequestBodyError(w http.ResponseWriter, err error) {
	var rbe *requestBodyError
	if !errors.As(err, &rbe) {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if rbe.status == http.StatusUnsupportedMediaType {
		w.Header().Set("Accept-Encoding", acceptedRequestEncodings)
	}
	http.Error(w, rbe.msg, rbe.status)
}

// contentCoding is one supported HTTP content coding.
type contentCoding struct {
	name   string
	decode func(io.Reader) (io.ReadCloser, error)
	encode func(io.Writer) (io.WriteCloser, error)
}

var (
	gzipCoding = &contentCoding{
		name:   "gzip",
		decode: func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) },
		encode: func(w io.Writer) (io.WriteCloser, error) { return gzip.NewWriter(w), nil },
	}
	// HTTP "deflate" is the zlib format (RFC 9110 §8.4.1.2), not a raw deflate stream.
	deflateCoding = &contentCoding{
		name:   "deflate",
		decode: decodeZlib,
		encode: func(w io.Writer) (io.WriteCloser, error) { return zlib.NewWriter(w), nil },
	}
	zstdCoding = &contentCoding{
		name: "zstd",
		decode: func(r io.Reader) (io.ReadCloser, error) {
			d, err := zstd.NewReader(r, zstdDecoderOptions...)
			if err != nil {
				return nil, err
			}
			return d.IOReadCloser(), nil
		},
		encode: func(w io.Writer) (io.WriteCloser, error) { return zstd.NewWriter(w, zstdEncoderOptions...) },
	}
)

// supportedCodings maps lower-cased Content-Encoding tokens to codings.
// "x-gzip" is the legacy alias recipients treat as gzip (RFC 9110 §8.4.1.3).
var supportedCodings = map[string]*contentCoding{
	"gzip":    gzipCoding,
	"x-gzip":  gzipCoding,
	"deflate": deflateCoding,
	"zstd":    zstdCoding,
}

// parseContentEncoding returns the codings applied to a body, in the order
// they were applied, from all Content-Encoding header lines. "identity" and
// empty list members are no-ops. Any other unknown coding is a 415.
func parseContentEncoding(values []string) ([]*contentCoding, error) {
	var codings []*contentCoding
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if tok == "" || tok == "identity" {
				continue
			}
			c, ok := supportedCodings[tok]
			if !ok {
				// The token is client-controlled header data; it is kept out of
				// the error because callers log it.
				return nil, &requestBodyError{
					status: http.StatusUnsupportedMediaType,
					msg:    "unsupported Content-Encoding",
					err:    errUnsupportedCoding,
				}
			}
			codings = append(codings, c)
		}
	}
	return codings, nil
}

// codingNames renders codings as a Content-Encoding header value.
func codingNames(codings []*contentCoding) string {
	names := make([]string, len(codings))
	for i, c := range codings {
		names[i] = c.name
	}
	return strings.Join(names, ", ")
}

// decodeBody removes codings (applied in slice order) from wire. Decoding is
// streamed; only the fully decoded body is buffered. Malformed, truncated or
// trailing data in any layer is a 400.
func decodeBody(wire []byte, codings []*contentCoding) ([]byte, error) {
	if len(codings) == 0 {
		return wire, nil
	}
	var src io.Reader = bytes.NewReader(wire)
	for i := len(codings) - 1; i >= 0; i-- {
		rc, err := codings[i].decode(src)
		if err != nil {
			return nil, badRequestBody(fmt.Errorf("%s: %w", codings[i].name, err))
		}
		// Close errors repeat a decode error already returned by ReadAll below.
		defer func() { _ = rc.Close() }()
		src = rc
	}
	decoded, err := io.ReadAll(src)
	if err != nil {
		return nil, badRequestBody(fmt.Errorf("decode %s: %w", codingNames(codings), err))
	}
	return decoded, nil
}

// encodeBody applies codings, in slice order, to data and writes the result
// to dst.
func encodeBody(dst io.Writer, data []byte, codings []*contentCoding) error {
	writers := make([]io.WriteCloser, 0, len(codings))
	w := dst
	for i := len(codings) - 1; i >= 0; i-- {
		wc, err := codings[i].encode(w)
		if err != nil {
			return fmt.Errorf("%s encoder: %w", codings[i].name, err)
		}
		writers = append(writers, wc)
		w = wc
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("encode %s: %w", codingNames(codings), err)
	}
	// Close the first-applied coding first so each layer flushes into the next.
	for i := len(writers) - 1; i >= 0; i-- {
		if err := writers[i].Close(); err != nil {
			return fmt.Errorf("finish %s: %w", codingNames(codings), err)
		}
	}
	return nil
}

// errUnsupportedCoding reports a Content-Encoding token outside supportedCodings.
var errUnsupportedCoding = errors.New("content coding is not supported")

// errTrailingData reports bytes after the end of a compressed stream.
var errTrailingData = errors.New("trailing data after compressed stream")

// decodeZlib decodes the HTTP "deflate" coding. Unlike gzip and zstd, the zlib
// reader stops at the end of the stream without looking at what follows, so
// trailing bytes are checked explicitly. Reading through our own bufio.Reader
// (a flate.Reader) keeps zlib from adding a read-ahead buffer we cannot see.
func decodeZlib(src io.Reader) (io.ReadCloser, error) {
	br := bufio.NewReader(src)
	zr, err := zlib.NewReader(br)
	if err != nil {
		return nil, err
	}
	return &zlibStrictEOF{ReadCloser: zr, src: br}, nil
}

type zlibStrictEOF struct {
	io.ReadCloser
	src *bufio.Reader
}

func (z *zlibStrictEOF) Read(p []byte) (int, error) {
	n, err := z.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		if _, peekErr := z.src.Peek(1); peekErr == nil {
			return n, errTrailingData
		}
	}
	return n, err
}

// isDeclaredJSON reports whether a Content-Type declares a JSON body:
// application/json or any structured "+json" media type (RFC 6839).
func isDeclaredJSON(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}
