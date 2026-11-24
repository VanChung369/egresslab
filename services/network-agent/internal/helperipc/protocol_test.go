package helperipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Request{Version: Version, Operation: OpRecoverScan}

	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, want); err != nil {
		t.Fatal(err)
	}

	var got Request
	if err := ReadFrame(&buffer, &got); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestFrameRejectsBadInput(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte("")},
		{"unknown field", []byte(`{"version":1,"operation":"Ping","command":"rm"}`)},
		{"invalid json", []byte(`{"version":`)},
		{"trailing json", []byte(`{"version":1,"operation":"Ping"}{}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buffer bytes.Buffer
			_ = binary.Write(&buffer, binary.BigEndian, uint32(len(tt.payload)))
			buffer.Write(tt.payload)

			var req Request
			if err := ReadFrame(&buffer, &req); !errors.Is(err, ErrInvalidFrame) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	t.Run("oversized header", func(t *testing.T) {
		var huge bytes.Buffer
		_ = binary.Write(&huge, binary.BigEndian, uint32(MaxFrameBytes+1))

		var req Request
		if err := ReadFrame(&huge, &req); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("oversized frame accepted: %v", err)
		}
	})

	t.Run("truncated body", func(t *testing.T) {
		var short bytes.Buffer
		_ = binary.Write(&short, binary.BigEndian, uint32(100))
		short.WriteString(`{"version":1}`)

		var req Request
		if err := ReadFrame(&short, &req); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("truncated frame accepted: %v", err)
		}
	})
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var buffer bytes.Buffer
	big := Response{Version: Version, Error: strings.Repeat("x", MaxFrameBytes)}

	if err := WriteFrame(&buffer, big); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("oversized payload written: %v", err)
	}

	if buffer.Len() != 0 {
		t.Fatalf("%d bytes written for a rejected frame", buffer.Len())
	}
}

func TestCallRefusesUnlistedOperations(t *testing.T) {
	// The client refuses before dialling, so the socket path is never used.
	for _, op := range []string{"CreateLab", "ConnectTunnel", "RecoverClean", ""} {
		if _, err := Call(context.Background(), "/nonexistent/helper.sock", op); err == nil ||
			!strings.Contains(err.Error(), "not available") {
			t.Fatalf("%q: %v", op, err)
		}
	}
}
