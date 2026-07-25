package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BipinRimal314/chokepoint/internal/jsonrpc"
)

// harness wires a session to in-memory streams and runs it.
type harness struct {
	clientOut *syncBuffer // what the agent receives
	serverIn  *syncBuffer // what the tool server receives
	done      chan error
}

// syncBuffer is a bytes.Buffer safe for concurrent write and read, which the
// two pump goroutines require.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) lines() []string {
	s := strings.TrimRight(b.String(), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func run(t *testing.T, fromClient, fromServer string, opts Options) *harness {
	t.Helper()

	h := &harness{
		clientOut: &syncBuffer{},
		serverIn:  &syncBuffer{},
		done:      make(chan error, 1),
	}

	sess := NewSession(Streams{
		ClientIn:  strings.NewReader(fromClient),
		ClientOut: h.clientOut,
		ServerIn:  h.serverIn,
		ServerOut: strings.NewReader(fromServer),
	}, opts)

	go func() { h.done <- sess.Run(context.Background()) }()
	return h
}

func (h *harness) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-h.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("session did not finish within 5s")
		return nil
	}
}

func TestTransparentWithNoInterceptor(t *testing.T) {
	// Unusual key order and an unknown field: a transparent proxy must not
	// normalise either.
	req := `{"id":1,"jsonrpc":"2.0","method":"tools/call","_meta":{"trace":"abc"}}`
	resp := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`

	h := run(t, req+"\n", resp+"\n", Options{})
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := h.serverIn.lines(); len(got) != 1 || got[0] != req {
		t.Errorf("server received %q, want %q", got, req)
	}
	if got := h.clientOut.lines(); len(got) != 1 || got[0] != resp {
		t.Errorf("client received %q, want %q", got, resp)
	}
}

func TestRejectRepliesToSenderAndDoesNotForward(t *testing.T) {
	req := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"shell"}}`

	opts := Options{
		Interceptor: InterceptorFunc(func(_ context.Context, dir Direction, msg *jsonrpc.Message) (Interception, error) {
			if dir != ClientToServer || msg.Method != "tools/call" {
				return Interception{Decision: Forward}, nil
			}
			reply, err := jsonrpc.ErrorResponse(msg.ID, jsonrpc.CodePolicyDenied, "denied", nil)
			if err != nil {
				return Interception{}, err
			}
			return Interception{Decision: Reject, Message: reply}, nil
		}),
	}

	h := run(t, req+"\n", "", opts)
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := h.serverIn.String(); got != "" {
		t.Errorf("rejected request reached the server: %q", got)
	}

	lines := h.clientOut.lines()
	if len(lines) != 1 {
		t.Fatalf("client got %d messages, want 1: %q", len(lines), lines)
	}
	reply, err := jsonrpc.Parse([]byte(lines[0]))
	if err != nil {
		t.Fatalf("reply does not parse: %v", err)
	}
	if !reply.IsResponse() {
		t.Error("reply is not a response")
	}
	// The id must match so the waiting client can correlate it.
	if reply.IDKey() != "42" {
		t.Errorf("reply id = %s, want 42", reply.ID)
	}
}

func TestReplaceSendsRewrittenMessage(t *testing.T) {
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"path":"/etc/shadow"}}`
	redacted := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"path":"[REDACTED]"}}`

	opts := Options{
		Interceptor: InterceptorFunc(func(_ context.Context, dir Direction, _ *jsonrpc.Message) (Interception, error) {
			if dir == ClientToServer {
				return Interception{Decision: Replace, Message: []byte(redacted)}, nil
			}
			return Interception{Decision: Forward}, nil
		}),
	}

	h := run(t, req+"\n", "", opts)
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := h.serverIn.lines()
	if len(got) != 1 || got[0] != redacted {
		t.Errorf("server received %q, want %q", got, redacted)
	}
}

func TestDropDiscardsNotification(t *testing.T) {
	note := `{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`

	opts := Options{
		Interceptor: InterceptorFunc(func(context.Context, Direction, *jsonrpc.Message) (Interception, error) {
			return Interception{Decision: Drop}, nil
		}),
	}

	h := run(t, note+"\n", "", opts)
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := h.serverIn.String(); got != "" {
		t.Errorf("dropped notification was forwarded: %q", got)
	}
}

func TestDropOnRequestIsAnError(t *testing.T) {
	// Dropping a request leaves the sender waiting forever. The proxy must
	// refuse rather than silently strand the session.
	req := `{"jsonrpc":"2.0","id":9,"method":"tools/call"}`

	opts := Options{
		Interceptor: InterceptorFunc(func(context.Context, Direction, *jsonrpc.Message) (Interception, error) {
			return Interception{Decision: Drop}, nil
		}),
	}

	h := run(t, req+"\n", "", opts)
	err := h.wait(t)
	if err == nil {
		t.Fatal("expected an error when a request is dropped")
	}
	if !strings.Contains(err.Error(), "use Reject") {
		t.Errorf("err = %v, want guidance to use Reject", err)
	}
}

func TestUnparseableMessageIsForwardedAndReported(t *testing.T) {
	// Not JSON-RPC, but possibly a protocol extension this build predates.
	// A transparent proxy forwards it and lets the endpoint decide.
	junk := `{"some":"other-protocol"}`

	var reported atomic.Int32
	opts := Options{
		OnError: func(Direction, error) { reported.Add(1) },
	}

	h := run(t, junk+"\n", "", opts)
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := h.serverIn.lines(); len(got) != 1 || got[0] != junk {
		t.Errorf("server received %q, want the message forwarded unchanged", got)
	}
	if reported.Load() != 1 {
		t.Errorf("OnError called %d times, want 1", reported.Load())
	}
}

func TestInterceptorErrorEndsSession(t *testing.T) {
	boom := errors.New("policy engine unavailable")
	opts := Options{
		Interceptor: InterceptorFunc(func(context.Context, Direction, *jsonrpc.Message) (Interception, error) {
			return Interception{}, boom
		}),
	}

	h := run(t, `{"jsonrpc":"2.0","id":1,"method":"a"}`+"\n", "", opts)
	err := h.wait(t)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestInFlightRepliesSurviveClientClose(t *testing.T) {
	// Regression: a client that writes a batch of requests and closes its end
	// must still receive the answers. Tearing the session down on client EOF
	// dropped nearly every reply — caught end-to-end, not by the earlier
	// unit tests, because it only shows up when the upstream replies after
	// the client has already finished sending.
	const n = 40

	var requests strings.Builder
	for i := 0; i < n; i++ {
		requests.WriteString(`{"jsonrpc":"2.0","id":` + itoa(i) + `,"method":"tools/call"}` + "\n")
	}

	serverOut, serverWriter := io.Pipe()
	serverIn := &closableBuffer{closed: make(chan struct{})}

	sess := NewSession(Streams{
		ClientIn:  strings.NewReader(requests.String()),
		ClientOut: &syncBuffer{},
		ServerIn:  serverIn,
		ServerOut: serverOut,
	}, Options{})

	clientOut := &syncBuffer{}
	sess.streams.ClientOut = clientOut
	sess.clientW = jsonrpc.NewWriter(clientOut)

	done := make(chan error, 1)
	go func() { done <- sess.Run(context.Background()) }()

	// The upstream replies only after its stdin is closed, which is exactly
	// the window the bug lost.
	go func() {
		<-serverIn.closed
		for i := 0; i < n; i++ {
			_, _ = serverWriter.Write([]byte(
				`{"jsonrpc":"2.0","id":` + itoa(i) + `,"result":{}}` + "\n"))
		}
		_ = serverWriter.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session did not finish")
	}

	if got := len(clientOut.lines()); got != n {
		t.Errorf("client received %d replies, want %d", got, n)
	}
}

// closableBuffer records when it is closed, so a test can act on the proxy
// signalling end-of-input to the upstream.
type closableBuffer struct {
	syncBuffer
	once   sync.Once
	closed chan struct{}
}

func (b *closableBuffer) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestServerExitTearsDownTheSession(t *testing.T) {
	// A tool server that exits leaves the agent waiting on a reply that can
	// never arrive. The client pump must not stay blocked on its read.
	clientIn, clientWriter := io.Pipe()
	defer clientWriter.Close()

	sess := NewSession(Streams{
		ClientIn:  clientIn,
		ClientOut: &syncBuffer{},
		ServerIn:  &syncBuffer{},
		ServerOut: strings.NewReader(""), // server closes immediately
	}, Options{})

	done := make(chan error, 1)
	go func() { done <- sess.Run(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not tear down after the server closed")
	}
}

func TestContextCancellationStopsSession(t *testing.T) {
	clientIn, clientWriter := io.Pipe()
	defer clientWriter.Close()
	serverOut, serverWriter := io.Pipe()
	defer serverWriter.Close()

	sess := NewSession(Streams{
		ClientIn:  clientIn,
		ClientOut: &syncBuffer{},
		ServerIn:  &syncBuffer{},
		ServerOut: serverOut,
	}, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sess.Run(ctx) }()

	// Let the pumps block on their reads, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Unblock both reads so the pumps reach their next context check.
	go func() {
		_, _ = clientWriter.Write([]byte(`{"jsonrpc":"2.0","method":"x"}` + "\n"))
		_, _ = serverWriter.Write([]byte(`{"jsonrpc":"2.0","method":"y"}` + "\n"))
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not stop after context cancellation")
	}
}

func TestBothDirectionsAreIntercepted(t *testing.T) {
	var seen sync.Map
	opts := Options{
		Interceptor: InterceptorFunc(func(_ context.Context, dir Direction, msg *jsonrpc.Message) (Interception, error) {
			seen.Store(dir.String(), msg.Method)
			return Interception{Decision: Forward}, nil
		}),
	}

	h := run(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`+"\n",
		`{"jsonrpc":"2.0","method":"notifications/message"}`+"\n",
		opts)
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if v, ok := seen.Load(ClientToServer.String()); !ok || v != "tools/call" {
		t.Errorf("client->server saw %v, want tools/call", v)
	}
	if v, ok := seen.Load(ServerToClient.String()); !ok || v != "notifications/message" {
		t.Errorf("server->client saw %v, want notifications/message", v)
	}
}

func TestManyMessagesPreserveOrderAndContent(t *testing.T) {
	const n = 500
	var in strings.Builder
	for i := 0; i < n; i++ {
		enc, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": i, "method": "tools/call",
		})
		in.Write(enc)
		in.WriteByte('\n')
	}

	h := run(t, in.String(), "", Options{})
	if err := h.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	lines := h.serverIn.lines()
	if len(lines) != n {
		t.Fatalf("server got %d messages, want %d", len(lines), n)
	}
	for i, line := range lines {
		msg, err := jsonrpc.Parse([]byte(line))
		if err != nil {
			t.Fatalf("message %d does not parse: %v", i, err)
		}
		if msg.IDKey() != json.Number(string(rune(0))).String() && msg.IDKey() != itoa(i) {
			t.Fatalf("message %d has id %s, want %d (order not preserved)", i, msg.ID, i)
		}
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
