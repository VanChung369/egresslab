package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

func proxyCapabilityFrame(t *testing.T) []byte {
	t.Helper()

	binding, err := helperauth.NewPrepareEgressLeaseIntent("profile_0123456789abcdef", "egresslab-lab-0123456789abcdef",
		"9.9.9.9", "tunnelgen_0123456789abcdef0123456789abcdef", "ffeeddccbbaa99887766554433221100",
		"aabbccddeeff00112233445566778899", "runtime_0123456789abcdef0123456789abcdef",
		"authority_0123456789abcdef0123456789abcdef", "reservation_0123456789abcdef0123456789abcdef", "8.8.4.4")
	if err != nil {
		t.Fatal(err)
	}

	intent, err := helperauth.NewOpenProxyStreamIntent(binding, testStreamDestination)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(helperauth.SignedCapability{Claims: helperauth.Claims{Version: 1, Intent: intent}})
	if err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 4, 4+len(raw))
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))

	return append(frame, raw...)
}

func streamFrame(kind byte, data []byte) []byte {
	frame := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[1:], uint32(len(data)))

	return append(frame, data...)
}

// fakeStreamHelper acknowledges one stream request. "echo" echoes until the client half-closes;
// "fin-first" sends its data, half-closes at once, and records what the client still uploads.
func fakeStreamHelper(t *testing.T, mode string) (string, <-chan []byte) {
	t.Helper()

	dir, err := os.MkdirTemp("", "elctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "helper.sock")

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	uploaded := make(chan []byte, 1)

	go func() {
		conn, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer conn.Close()

		var req helperipc.Request
		if helperipc.ReadFrame(conn, &req) != nil || req.Operation != helperauth.OpOpenProxyStream {
			return
		}

		_ = helperipc.WriteFrame(conn, helperipc.ProxyStreamAck{Version: 1, Operation: req.Operation, OK: true,
			BoundIPv4: "10.0.0.2", BoundPort: 40000})

		if mode == "fin-first" {
			_, _ = conn.Write([]byte("server-data"))
			_ = conn.CloseWrite()

			data, _ := io.ReadAll(conn)
			uploaded <- data

			return
		}

		_, _ = io.Copy(conn, conn)
		_ = conn.CloseWrite()
	}()

	return path, uploaded
}

// streamSession runs runProxyStream over pipes, as the controller does.
type streamSession struct {
	input  *io.PipeWriter
	output *io.PipeReader
	done   chan error
}

func startStream(t *testing.T) *streamSession {
	t.Helper()

	stdin, input := io.Pipe()
	output, stdout := io.Pipe()
	s := &streamSession{input: input, output: output, done: make(chan error, 1)}

	go func() {
		err := runProxyStream(stdin, stdout)
		_ = stdout.Close()
		s.done <- err
	}()

	t.Cleanup(func() { _ = input.Close(); _ = output.Close() })

	if _, err := input.Write(proxyCapabilityFrame(t)); err != nil {
		t.Fatal(err)
	}

	var ack helperipc.ProxyStreamAck
	if err := helperipc.ReadFrame(output, &ack); err != nil || !ack.OK || ack.BoundIPv4 != "10.0.0.2" {
		t.Fatalf("no acknowledgement frame: %+v %v", ack, err)
	}

	return s
}

// readUntil reads frames until one of kind arrives and returns the data before it.
func (s *streamSession) readUntil(t *testing.T, kind byte) []byte {
	t.Helper()

	var data []byte

	for {
		var header [5]byte
		if _, err := io.ReadFull(s.output, header[:]); err != nil {
			t.Fatalf("stream ended before %q: %v", kind, err)
		}

		chunk := make([]byte, binary.BigEndian.Uint32(header[1:]))
		if _, err := io.ReadFull(s.output, chunk); err != nil {
			t.Fatal(err)
		}

		switch header[0] {
		case streamFrameData:
			data = append(data, chunk...)
		case kind:
			return data
		default:
			t.Fatalf("unexpected frame %q", header[0])
		}
	}
}

func (s *streamSession) close(t *testing.T) {
	t.Helper()

	_ = s.input.Close()

	go func() { _, _ = io.Copy(io.Discard, s.output) }()

	select {
	case err := <-s.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not end when stdin closed")
	}
}

var testStreamDestination = netipMustParse("93.184.216.34:443")

func TestProxyStreamMode(t *testing.T) {
	socketPath, _ = fakeStreamHelper(t, "echo")
	t.Cleanup(func() { socketPath = helperipc.SocketPath })

	s := startStream(t)
	payload := bytes.Repeat([]byte{0, 'D', 'F', 'E', 0xff}, 20000)

	go func() {
		for rest := payload; len(rest) > 0; {
			n := min(len(rest), maxStreamFrameBytes)
			_, _ = s.input.Write(streamFrame(streamFrameData, rest[:n]))
			rest = rest[n:]
		}

		_, _ = s.input.Write(streamFrame(streamFrameFin, nil))
	}()

	if data := s.readUntil(t, streamFrameFin); !bytes.Equal(data, payload) {
		t.Fatalf("stream not relayed byte for byte: %d of %d bytes", len(data), len(payload))
	}

	s.close(t)
}

// The destination's FIN does not end the stream: the client's upload still arrives.
func TestProxyStreamUploadAfterDestinationFin(t *testing.T) {
	var uploaded <-chan []byte

	socketPath, uploaded = fakeStreamHelper(t, "fin-first")
	t.Cleanup(func() { socketPath = helperipc.SocketPath })

	s := startStream(t)

	if data := s.readUntil(t, streamFrameFin); string(data) != "server-data" {
		t.Fatalf("unexpected download: %q", data)
	}

	if _, err := s.input.Write(streamFrame(streamFrameData, []byte("late upload"))); err != nil {
		t.Fatal(err)
	}

	if _, err := s.input.Write(streamFrame(streamFrameFin, nil)); err != nil {
		t.Fatal(err)
	}

	select {
	case data := <-uploaded:
		if string(data) != "late upload" {
			t.Fatalf("upload truncated: %q", data)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upload never arrived")
	}

	s.close(t)
}

func TestProxyStreamModeRefusesBadCapability(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":     nil,
		"truncated": {0, 0, 0, 10, '{'},
		"not JSON":  append([]byte{0, 0, 0, 3}, "abc"...),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer

			if err := runProxyStream(bytes.NewReader(input), &stdout); err == nil {
				t.Fatal("bad capability accepted")
			}

			var ack helperipc.ProxyStreamAck
			if err := helperipc.ReadFrame(&stdout, &ack); err != nil || ack.OK || ack.Code != helperipc.CodeInvalidRequest ||
				stdout.Len() != 0 {
				t.Fatalf("expected one failure frame: %+v %v", ack, err)
			}
		})
	}
}

func netipMustParse(raw string) netip.AddrPort { return netip.MustParseAddrPort(raw) }
