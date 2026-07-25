// Package jsonrpc implements just enough of JSON-RPC 2.0 to proxy the Model
// Context Protocol without understanding every message.
//
// The central design constraint is fidelity. chokepoint sits between an agent
// and its tool servers, and anything it does not specifically intend to change
// must arrive byte-for-byte as it was sent. Decoding a message into a struct
// and re-encoding it would quietly reorder object keys, drop fields this
// version has never heard of, and renumber floats — all invisible until an
// upstream server rejects a request for reasons nobody can reproduce.
//
// So every message keeps its original bytes. Fields are decoded lazily, only
// when a policy actually asks about them, and a message that is forwarded
// unmodified is forwarded as the exact bytes that arrived.
package jsonrpc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Version is the only JSON-RPC version MCP uses.
const Version = "2.0"

// Message is a single JSON-RPC message with its original encoding preserved.
//
// Raw is authoritative. The decoded fields are a view of it, and callers that
// forward a message unchanged must write Raw rather than re-marshalling.
type Message struct {
	// Raw is the exact bytes as they arrived, without a trailing newline.
	Raw []byte

	// ID is the request identifier. JSON-RPC allows a string, a number, or
	// null, so it stays as raw JSON rather than being forced into a Go type.
	// Nil means the message is a notification.
	ID json.RawMessage

	// Method is empty for responses.
	Method string

	// Params is the raw params value, nil when absent.
	Params json.RawMessage

	// Result and Error are set only on responses; exactly one is non-nil.
	Result json.RawMessage
	Error  json.RawMessage
}

// envelope mirrors the wire format for decoding only.
type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ErrNotJSONRPC reports a line that parsed as JSON but is not a JSON-RPC message.
var ErrNotJSONRPC = errors.New("not a JSON-RPC 2.0 message")

// Parse decodes one message, retaining its original bytes.
//
// The caller keeps ownership of raw; Parse does not copy it, because the
// message lives only as long as the pump iteration that produced it.
func Parse(raw []byte) (*Message, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode json-rpc: %w", err)
	}
	if env.JSONRPC != Version {
		return nil, ErrNotJSONRPC
	}

	return &Message{
		Raw:    raw,
		ID:     env.ID,
		Method: env.Method,
		Params: env.Params,
		Result: env.Result,
		Error:  env.Error,
	}, nil
}

// IsRequest reports whether the message expects a response.
func (m *Message) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
}

// IsNotification reports whether the message is a one-way notification.
func (m *Message) IsNotification() bool {
	return m.Method != "" && (len(m.ID) == 0 || string(m.ID) == "null")
}

// IsResponse reports whether the message answers an earlier request.
func (m *Message) IsResponse() bool {
	return m.Method == "" && (m.Result != nil || m.Error != nil)
}

// IDKey returns a comparable key for correlating a response to its request.
//
// JSON-RPC permits both `"id": 1` and `"id": "1"`, which are distinct
// identifiers. Using the raw encoding as the key keeps them distinct, where
// converting both to a Go string would collide them.
func (m *Message) IDKey() string {
	if len(m.ID) == 0 {
		return ""
	}
	return string(m.ID)
}

// Standard JSON-RPC error codes, plus the application-defined code chokepoint
// uses for policy denials.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// CodePolicyDenied sits in the implementation-defined server error range
	// (-32000 to -32099) reserved by the spec for application use.
	CodePolicyDenied = -32001
)

// ErrorResponse builds a well-formed JSON-RPC error reply for the given id.
//
// A denied tool call must look to the client exactly like a tool that refused
// the request: same shape, correlated id, connection intact. Dropping the
// connection instead would turn a policy decision into an outage, and would
// teach agent authors that chokepoint is a source of flakiness rather than a
// source of answers.
func ErrorResponse(id json.RawMessage, code int, message string, data any) ([]byte, error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}

	errObj := map[string]any{
		"code":    code,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}

	return json.Marshal(map[string]any{
		"jsonrpc": Version,
		"id":      id,
		"error":   errObj,
	})
}
