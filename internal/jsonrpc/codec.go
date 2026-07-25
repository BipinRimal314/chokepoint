package jsonrpc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"
)

// DefaultMaxMessageBytes bounds a single message.
//
// A proxy reading attacker-influenced input must have a ceiling: without one,
// a stream with no newline is an unbounded allocation and chokepoint becomes
// the easiest way to kill the agent it protects. Tool results carrying file
// contents are legitimately large, so the limit is generous rather than tight.
const DefaultMaxMessageBytes = 16 << 20 // 16 MiB

// ErrMessageTooLarge is returned when a message exceeds the configured limit.
var ErrMessageTooLarge = errors.New("jsonrpc: message exceeds maximum size")

// Reader reads newline-delimited JSON-RPC messages from a stream.
//
// MCP's stdio transport frames messages by newline and forbids embedded
// newlines in the encoding, so a line is a message.
type Reader struct {
	scanner *bufio.Scanner
	maxSize int
}

// NewReader returns a Reader over r, allowing messages up to maxSize bytes.
// A maxSize of zero uses DefaultMaxMessageBytes.
func NewReader(r io.Reader, maxSize int) *Reader {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageBytes
	}
	scanner := bufio.NewScanner(r)
	// bufio.Scanner defaults to a 64 KiB ceiling and returns bufio.ErrTooLong
	// past it. Tool results routinely exceed that, and the failure mode is a
	// silently truncated session, so the ceiling is raised to the real limit.
	//
	// The starting capacity must not exceed maxSize: Scanner.Buffer documents
	// the effective maximum as the larger of max and cap(buf), so a generous
	// starting buffer silently overrides a smaller configured limit.
	start := 64 << 10
	if maxSize < start {
		start = maxSize
	}
	scanner.Buffer(make([]byte, 0, start), maxSize)
	return &Reader{scanner: scanner, maxSize: maxSize}
}

// ReadRaw returns the next message's bytes, excluding the newline.
//
// The returned slice is only valid until the next call: it aliases the
// scanner's buffer. Callers that retain a message past the next read must copy
// it. This is deliberate — the pump forwards each message immediately, and
// copying every message on a hot path would double the proxy's allocation rate
// for no benefit.
func (r *Reader) ReadRaw() ([]byte, error) {
	for {
		if !r.scanner.Scan() {
			if err := r.scanner.Err(); err != nil {
				if errors.Is(err, bufio.ErrTooLong) {
					return nil, fmt.Errorf("%w (limit %d bytes)", ErrMessageTooLarge, r.maxSize)
				}
				return nil, err
			}
			return nil, io.EOF
		}
		line := r.scanner.Bytes()
		// Blank lines are not messages. Some servers emit them as keepalives.
		if len(trimSpace(line)) == 0 {
			continue
		}
		return line, nil
	}
}

// trimSpace reports the line with leading and trailing ASCII whitespace removed.
// Written out rather than using bytes.TrimSpace to avoid its UTF-8 decoding on
// a path that runs for every message.
func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// Writer writes newline-delimited JSON-RPC messages to a stream.
//
// Writes are serialized by a mutex. Two goroutines can legitimately write to
// the same downstream at once — a forwarded upstream response and a locally
// generated policy denial — and interleaving two messages would produce a
// stream neither side can parse.
type Writer struct {
	mu  sync.Mutex
	w   *bufio.Writer
	dst io.Writer
}

// NewWriter returns a Writer over w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriter(w), dst: w}
}

// WriteRaw writes one message followed by a newline, then flushes.
//
// Flushing on every message is intentional. This is an interactive
// request/response protocol where the peer is blocked waiting; buffering a
// reply to batch it with the next one would deadlock a session that has only
// one message in flight.
func (w *Writer) WriteRaw(msg []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.w.Write(msg); err != nil {
		return err
	}
	if err := w.w.WriteByte('\n'); err != nil {
		return err
	}
	return w.w.Flush()
}
