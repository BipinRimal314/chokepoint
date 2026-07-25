package jsonrpc

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestParseClassifiesMessageKinds(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		request      bool
		notification bool
		response     bool
	}{
		{
			name:    "request",
			raw:     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
			request: true,
		},
		{
			name:         "notification has no id",
			raw:          `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			notification: true,
		},
		{
			name:         "explicit null id is a notification",
			raw:          `{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}`,
			notification: true,
		},
		{
			name:     "result response",
			raw:      `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`,
			response: true,
		},
		{
			name:     "error response",
			raw:      `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`,
			response: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := Parse([]byte(tt.raw))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := msg.IsRequest(); got != tt.request {
				t.Errorf("IsRequest = %v, want %v", got, tt.request)
			}
			if got := msg.IsNotification(); got != tt.notification {
				t.Errorf("IsNotification = %v, want %v", got, tt.notification)
			}
			if got := msg.IsResponse(); got != tt.response {
				t.Errorf("IsResponse = %v, want %v", got, tt.response)
			}
		})
	}
}

func TestParseRejectsNonJSONRPC(t *testing.T) {
	// A bare JSON object is valid JSON but not a message we may forward as one.
	if _, err := Parse([]byte(`{"hello":"world"}`)); err != ErrNotJSONRPC {
		t.Fatalf("err = %v, want ErrNotJSONRPC", err)
	}
}

func TestParsePreservesRawBytesExactly(t *testing.T) {
	// Unusual key order, a float that would not survive a round trip, and a
	// field this package has never heard of. All must be preserved.
	raw := `{"id":7,"jsonrpc":"2.0","method":"tools/call","params":{"n":1.7000000000000002},"_meta":{"x":1}}`
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if string(msg.Raw) != raw {
		t.Errorf("Raw was modified:\n got %s\nwant %s", msg.Raw, raw)
	}
}

func TestIDKeyDistinguishesStringFromNumber(t *testing.T) {
	// `"id": 1` and `"id": "1"` are different identifiers. Collapsing them
	// would let one request's response be delivered for another's.
	num, err := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	str, err := Parse([]byte(`{"jsonrpc":"2.0","id":"1","method":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if num.IDKey() == str.IDKey() {
		t.Fatalf("numeric and string ids collided on key %q", num.IDKey())
	}
}

func TestErrorResponseIsWellFormedAndCorrelated(t *testing.T) {
	out, err := ErrorResponse(json.RawMessage(`"abc"`), CodePolicyDenied, "denied by policy", map[string]any{
		"rule": "no-shell",
	})
	if err != nil {
		t.Fatalf("ErrorResponse: %v", err)
	}

	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("generated response does not parse: %v", err)
	}
	if !msg.IsResponse() {
		t.Error("generated message is not a response")
	}
	if msg.IDKey() != `"abc"` {
		t.Errorf("id = %s, want \"abc\"", msg.ID)
	}

	var errObj struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(msg.Error, &errObj); err != nil {
		t.Fatalf("decode error object: %v", err)
	}
	if errObj.Code != CodePolicyDenied {
		t.Errorf("code = %d, want %d", errObj.Code, CodePolicyDenied)
	}
	if errObj.Data["rule"] != "no-shell" {
		t.Errorf("data.rule = %v, want no-shell", errObj.Data["rule"])
	}
}

func TestErrorResponseWithNoIDUsesNull(t *testing.T) {
	// The spec requires an id member even when the offending request had none.
	out, err := ErrorResponse(nil, CodeInvalidRequest, "bad", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"id":null`)) {
		t.Errorf("missing null id: %s", out)
	}
}

func TestReaderSkipsBlankLinesAndReturnsEOF(t *testing.T) {
	input := "\n" +
		`{"jsonrpc":"2.0","id":1,"method":"a"}` + "\n" +
		"   \n" +
		`{"jsonrpc":"2.0","id":2,"method":"b"}` + "\n"

	r := NewReader(strings.NewReader(input), 0)

	for _, want := range []string{`"id":1`, `"id":2`} {
		raw, err := r.ReadRaw()
		if err != nil {
			t.Fatalf("ReadRaw: %v", err)
		}
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("got %s, want message containing %s", raw, want)
		}
	}
	if _, err := r.ReadRaw(); err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

func TestReaderRejectsOversizedMessage(t *testing.T) {
	// A stream with no newline must not be an unbounded allocation.
	huge := `{"jsonrpc":"2.0","id":1,"method":"` + strings.Repeat("x", 4096) + `"}`
	r := NewReader(strings.NewReader(huge), 512)

	_, err := r.ReadRaw()
	if err == nil {
		t.Fatal("expected an error for an oversized message")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestReaderHandlesMessagesLargerThanDefaultScannerBuffer(t *testing.T) {
	// bufio.Scanner's own default is 64 KiB; a realistic tool result exceeds it.
	big := strings.Repeat("a", 200<<10)
	line := `{"jsonrpc":"2.0","id":1,"result":{"content":"` + big + `"}}`

	r := NewReader(strings.NewReader(line+"\n"), 0)
	raw, err := r.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if len(raw) != len(line) {
		t.Errorf("len = %d, want %d", len(raw), len(line))
	}
}

func TestWriterSerializesConcurrentWrites(t *testing.T) {
	// A forwarded response and a locally generated denial can race for the
	// same downstream. Interleaved bytes would corrupt both messages.
	var buf bytes.Buffer
	w := NewWriter(&buf)

	const writers = 16
	const perWriter = 32
	msg := []byte(`{"jsonrpc":"2.0","id":1,"result":{"padding":"` + strings.Repeat("z", 512) + `"}}`)

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if err := w.WriteRaw(msg); err != nil {
					t.Errorf("WriteRaw: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != writers*perWriter {
		t.Fatalf("got %d lines, want %d", len(lines), writers*perWriter)
	}
	for i, line := range lines {
		if !bytes.Equal(line, msg) {
			t.Fatalf("line %d was interleaved: %s", i, line)
		}
	}
}
