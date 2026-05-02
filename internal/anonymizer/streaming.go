package anonymizer

import (
	"bytes"
	"io"
	"log"
	"strings"
)

// tokenSuffixLen is the number of bytes kept unflushed in the streaming
// accumulator to guard against partial token splits. The longest possible
// token is [PII_CREDITCARD_XXXXXXXXXXXXXXXX] at 33 bytes (5 + 10 + 1 + 16 + 1).
const tokenSuffixLen = 33

// safeCutPoint returns the byte index up to which accumulated text can be
// safely flushed without splitting a partial PII token. It scans backward
// from the suffix guard boundary looking for an unmatched '['.
// Returns 0 if all text should be held in the accumulator.
func safeCutPoint(accumulated string) int {
	if len(accumulated) <= tokenSuffixLen {
		return 0
	}

	cutAt := len(accumulated) - tokenSuffixLen
	// Scan backward from the end of the string looking for '['.
	// If an unmatched '[' is found, pull cutAt back to avoid splitting a token.
	// If a matched '[' ... ']' bracket straddles cutAt (i.e. '[' is before cutAt
	// but ']' is at or after cutAt), pull cutAt back to the '[' position.
	// Complete brackets entirely before cutAt are safe to flush.
	for i := len(accumulated) - 1; i >= 0; i-- {
		if accumulated[i] == '[' {
			closeBracket := strings.IndexByte(accumulated[i:], ']')
			if closeBracket == -1 {
				// Unmatched '[' — hold everything from here.
				cutAt = i
			} else if i < cutAt && i+closeBracket >= cutAt {
				// Bracket straddles cutAt — hold the whole bracket.
				cutAt = i
			}
			// else: bracket is entirely within the flush zone, cutAt is fine.
			break
		}
	}
	return cutAt
}

// streamContext holds the mutable state shared by the streaming framework
// functions during a single StreamingDeanonymize invocation.
type streamContext struct {
	pw       *io.PipeWriter
	replacer *strings.Replacer
	provider StreamingDeanonymizer
}

// writePipe writes multiple byte slices to a PipeWriter, stopping on the
// first error. A write error means the reader side has been closed (client
// disconnected); continuing to write would be wasteful.
func writePipe(pw *io.PipeWriter, parts ...[]byte) {
	for _, p := range parts {
		if _, err := pw.Write(p); err != nil {
			return
		}
	}
}

// processLine handles one complete SSE line (without trailing newline).
// It delegates data payloads to the provider-specific StreamingDeanonymizer
// and passes through non-data lines with raw token replacement.
func processLine(ctx *streamContext, line []byte) {
	if len(line) == 0 || line[0] == ':' {
		ctx.pw.Write(line)         //nolint:errcheck
		ctx.pw.Write([]byte("\n")) //nolint:errcheck
		return
	}

	if !bytes.HasPrefix(line, []byte(sseDataPrefix)) {
		ctx.pw.Write([]byte(ctx.replacer.Replace(string(line)))) //nolint:errcheck
		ctx.pw.Write([]byte("\n"))                               //nolint:errcheck
		return
	}

	payload := line[len(sseDataPrefix):]
	if !ctx.provider.ProcessDataPayload(payload) {
		// Provider could not parse the payload — fall back to raw replacement.
		ctx.pw.Write([]byte(sseDataPrefix))                         //nolint:errcheck
		ctx.pw.Write([]byte(ctx.replacer.Replace(string(payload)))) //nolint:errcheck
		ctx.pw.Write([]byte("\n"))                                  //nolint:errcheck
	}
}

// assembleLines processes raw bytes from a read chunk, appending them to
// lineBuf. Each time a newline is encountered the complete line (with \r
// stripped) is dispatched to processLine and lineBuf is reset.
func assembleLines(chunk []byte, lineBuf []byte, ctx *streamContext) []byte {
	for _, b := range chunk {
		if b == '\n' {
			line := lineBuf
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			processLine(ctx, line)
			lineBuf = lineBuf[:0]
		} else {
			lineBuf = append(lineBuf, b)
		}
	}
	return lineBuf
}

// handleStreamEnd flushes any partial line and the provider's accumulated
// text when the source reader returns an error (including io.EOF).
func handleStreamEnd(lineBuf []byte, readErr error, ctx *streamContext) {
	if len(lineBuf) > 0 {
		ctx.pw.Write([]byte(ctx.replacer.Replace(string(lineBuf)))) //nolint:errcheck
	}
	ctx.provider.Flush()
	if readErr != io.EOF {
		log.Printf("[ANONYMIZER] StreamingDeanonymize read error: %v", readErr)
		ctx.pw.CloseWithError(readErr) //nolint:errcheck
	}
}

// readLoop reads from src, assembling complete lines and dispatching them
// to processLine. At EOF it flushes any remaining partial line and
// accumulated text via handleStreamEnd.
func readLoop(src io.ReadCloser, ctx *streamContext) {
	defer src.Close()    //nolint:errcheck
	defer ctx.pw.Close() //nolint:errcheck

	var lineBuf []byte
	const chunkSize = 32 * 1024
	buf := make([]byte, chunkSize)

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			lineBuf = assembleLines(buf[:n], lineBuf, ctx)
		}
		if readErr != nil {
			handleStreamEnd(lineBuf, readErr, ctx)
			return
		}
	}
}
