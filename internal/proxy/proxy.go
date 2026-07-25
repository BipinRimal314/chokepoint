// Package proxy pumps MCP traffic between a client and an upstream server,
// giving an interceptor a chance to inspect, rewrite, or answer each message.
//
// The proxy is transparent by default: with no interceptor configured, every
// message is forwarded as the exact bytes that arrived. That property is what
// makes chokepoint safe to put in front of a working system — it can be
// introduced first and given policy second.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/BipinRimal314/chokepoint/internal/jsonrpc"
)

// Direction identifies which way a message is travelling.
type Direction int

const (
	// ClientToServer is a request or notification from the agent.
	ClientToServer Direction = iota
	// ServerToClient is a response or notification from the tool server.
	ServerToClient
)

func (d Direction) String() string {
	if d == ClientToServer {
		return "client->server"
	}
	return "server->client"
}

// Decision is what an Interceptor wants done with a message.
type Decision int

const (
	// Forward sends the message on unchanged.
	Forward Decision = iota
	// Replace sends Interception.Message instead of the original.
	Replace
	// Reject answers the sender directly and does not forward anything.
	Reject
	// Drop silently discards the message. Only valid for notifications:
	// dropping a request would leave the sender waiting forever.
	Drop
)

// Interception is an Interceptor's verdict on one message.
type Interception struct {
	Decision Decision
	// Message carries the replacement bytes for Replace, or the reply to
	// return to the sender for Reject.
	Message []byte
}

// Interceptor inspects messages as they pass through.
//
// Implementations must be safe for concurrent use: the two directions are
// pumped by separate goroutines and will call Intercept simultaneously.
//
// The msg passed to Intercept, including msg.Raw and every json.RawMessage
// field, is only valid for the duration of the call — the bytes alias a read
// buffer that the next message overwrites. An Interceptor that retains
// anything derived from msg past its return must copy it first. Retaining
// extracted values (a tool name, a count) is fine; retaining the slices is not.
//
// An error aborts the session. Interceptors that want to fail open should
// return Forward and report the problem out of band rather than returning an
// error, because a policy engine that is briefly unavailable should not take
// the agent down with it.
type Interceptor interface {
	Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message) (Interception, error)
}

// InterceptorFunc adapts a function to the Interceptor interface.
type InterceptorFunc func(context.Context, Direction, *jsonrpc.Message) (Interception, error)

func (f InterceptorFunc) Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message) (Interception, error) {
	return f(ctx, dir, msg)
}

// Streams are the four endpoints a proxy session connects.
type Streams struct {
	// ClientIn is read for messages from the agent.
	ClientIn io.Reader
	// ClientOut is written with messages destined for the agent.
	ClientOut io.Writer
	// ServerIn is written with messages destined for the tool server.
	ServerIn io.Writer
	// ServerOut is read for messages from the tool server.
	ServerOut io.Reader
}

// Options configure a session.
type Options struct {
	// MaxMessageBytes bounds a single message; zero uses the codec default.
	MaxMessageBytes int
	// Interceptor is consulted for every message. Nil means pass everything
	// through untouched.
	Interceptor Interceptor
	// OnError receives non-fatal problems, such as a malformed message that
	// was forwarded anyway. Nil discards them.
	OnError func(dir Direction, err error)
	// DrainGrace bounds how long the session waits for the upstream to finish
	// replying after the client has closed its end. Zero uses
	// DefaultDrainGrace.
	DrainGrace time.Duration
}

// DefaultDrainGrace is how long an upstream gets to answer outstanding
// requests after the client stops sending.
//
// Generous, because the outstanding requests may be slow tool calls and
// cutting them off turns a completed action into a lost result. Bounded,
// because a server that ignores its closed stdin must not pin the process
// open forever.
const DefaultDrainGrace = 10 * time.Second

// Session is one client/server pairing.
type Session struct {
	streams Streams
	opts    Options

	clientW *jsonrpc.Writer
	serverW *jsonrpc.Writer
}

// NewSession returns a Session ready to Run.
func NewSession(streams Streams, opts Options) *Session {
	return &Session{
		streams: streams,
		opts:    opts,
		clientW: jsonrpc.NewWriter(streams.ClientOut),
		serverW: jsonrpc.NewWriter(streams.ServerIn),
	}
}

// Run pumps both directions until one closes or ctx is cancelled.
//
// Returns nil on a clean shutdown — either side closing its stream is the
// normal way an MCP session ends, not an error.
func (s *Session) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Shutdown requires actually unblocking a pump sitting in a blocking Read.
	// Cancelling the context does not interrupt a read already in progress, so
	// the sources are closed instead, which makes the pending read return.
	// Sources that are not io.Closer (a strings.Reader in a test) reach EOF on
	// their own.
	var closeOnce sync.Once
	stop := func() {
		closeOnce.Do(func() {
			for _, src := range []io.Reader{s.streams.ClientIn, s.streams.ServerOut} {
				if c, ok := src.(io.Closer); ok {
					_ = c.Close()
				}
			}
		})
	}
	go func() {
		<-ctx.Done()
		stop()
	}()

	var wg sync.WaitGroup
	errs := make(chan error, 2)

	// The two directions are deliberately NOT symmetric.
	//
	// The client closing its end means "no more requests", not "discard the
	// answers to the ones already sent". Tearing down here would drop every
	// reply still in flight — with a client that writes a batch of requests
	// and closes, that is nearly all of them. So this side signals
	// end-of-input to the upstream by closing its stdin and then waits.
	//
	// The server closing its end is different: nothing further can arrive, and
	// an agent left waiting on a reply would hang forever. That side ends the
	// session.
	wg.Add(2)

	go func() {
		defer wg.Done()
		errs <- s.pump(ctx, ClientToServer, s.streams.ClientIn, s.serverW)

		if c, ok := s.streams.ServerIn.(io.Closer); ok {
			_ = c.Close()
		}
		// A server that ignores its closed stdin would keep the session open
		// forever, so the wait for it to drain is bounded.
		go func() {
			select {
			case <-time.After(s.drainGrace()):
				cancel()
			case <-ctx.Done():
			}
		}()
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		errs <- s.pump(ctx, ServerToClient, s.streams.ServerOut, s.clientW)
	}()

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// pump moves messages in one direction until the source is exhausted.
func (s *Session) pump(ctx context.Context, dir Direction, src io.Reader, dst *jsonrpc.Writer) error {
	reader := jsonrpc.NewReader(src, s.opts.MaxMessageBytes)

	for {
		// Deliberately no ctx check before the read. Checking here would let a
		// cancellation race discard messages that are already buffered and
		// readable — when a short-lived server exits immediately, the client's
		// in-flight requests would vanish instead of being delivered. Shutdown
		// is driven by the source closing, which surfaces below as an error.
		raw, err := reader.ReadRaw()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			// A read failing because the session is shutting down is expected,
			// not a session error worth reporting.
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%s: read: %w", dir, err)
		}

		if err := s.handle(ctx, dir, raw, dst); err != nil {
			return err
		}
	}
}

// handle applies the interceptor to one message and routes the outcome.
func (s *Session) handle(ctx context.Context, dir Direction, raw []byte, dst *jsonrpc.Writer) error {
	msg, parseErr := jsonrpc.Parse(raw)
	if parseErr != nil {
		// Something unparseable is not necessarily an attack — it may be a
		// protocol extension this build predates. Forwarding it unchanged
		// keeps the proxy transparent and lets the real endpoint decide,
		// which is the same thing a network router does with a packet it does
		// not understand.
		s.reportError(dir, fmt.Errorf("forwarding unparseable message: %w", parseErr))
		return dst.WriteRaw(raw)
	}

	if s.opts.Interceptor == nil {
		return dst.WriteRaw(raw)
	}

	verdict, err := s.opts.Interceptor.Intercept(ctx, dir, msg)
	if err != nil {
		return fmt.Errorf("%s: interceptor: %w", dir, err)
	}

	switch verdict.Decision {
	case Forward:
		return dst.WriteRaw(raw)

	case Replace:
		if verdict.Message == nil {
			return fmt.Errorf("%s: interceptor returned Replace with no message", dir)
		}
		return dst.WriteRaw(verdict.Message)

	case Reject:
		if verdict.Message == nil {
			return fmt.Errorf("%s: interceptor returned Reject with no reply", dir)
		}
		// The reply goes back the way the message came, not onward.
		return s.replyTo(dir).WriteRaw(verdict.Message)

	case Drop:
		if msg.IsRequest() {
			// Dropping a request strands the sender on a reply that will
			// never arrive. An interceptor that wants a request gone must
			// Reject it so the sender gets an answer.
			return fmt.Errorf("%s: interceptor dropped request id %s; use Reject", dir, msg.IDKey())
		}
		return nil

	default:
		return fmt.Errorf("%s: unknown decision %d", dir, verdict.Decision)
	}
}

// drainGrace returns the configured drain window, or the default.
func (s *Session) drainGrace() time.Duration {
	if s.opts.DrainGrace > 0 {
		return s.opts.DrainGrace
	}
	return DefaultDrainGrace
}

// replyTo returns the writer that sends back toward the originator.
func (s *Session) replyTo(dir Direction) *jsonrpc.Writer {
	if dir == ClientToServer {
		return s.clientW
	}
	return s.serverW
}

func (s *Session) reportError(dir Direction, err error) {
	if s.opts.OnError != nil {
		s.opts.OnError(dir, err)
	}
}
