package labruntime

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

// TestFakeProxyHelperctl plays helperctl's proxy-stream mode in a child process.
func TestFakeProxyHelperctl(t *testing.T) {
	mode := os.Getenv("EGRESSLAB_FAKE_PROXY")
	if mode == "" {
		return
	}

	var header [4]byte
	if _, err := io.ReadFull(os.Stdin, header[:]); err != nil {
		os.Exit(2)
	}

	payload := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(os.Stdin, payload); err != nil {
		os.Exit(2)
	}

	var capability control.LabCapability
	if json.Unmarshal(payload, &capability) != nil || capability.Claims.Intent.Operation != control.LabOpenProxyStreamOp {
		os.Exit(2)
	}

	writeAck := func(ack string) {
		frame := make([]byte, 4, 4+len(ack))
		binary.BigEndian.PutUint32(frame, uint32(len(ack)))
		_, _ = os.Stdout.Write(append(frame, ack...))
	}

	switch mode {
	case "refuse":
		writeAck(`{"version":1,"operation":"OpenProxyStreamV1","ok":false,"code":"AUTHORIZATION_DENIED"}`)
		os.Exit(1)
	case "garbage":
		writeAck(`{"version":1,"operation":"OpenProxyStreamV1","ok":true,"bound_ipv4":"not-an-ip","bound_port":1}`)
		os.Exit(0)
	case "silent":
		time.Sleep(time.Minute)
		os.Exit(0)
	}

	writeAck(`{"version":1,"operation":"OpenProxyStreamV1","ok":true,"bound_ipv4":"10.0.0.2","bound_port":40000}`)

	writeFrame := func(kind byte, data []byte) {
		header := [5]byte{kind}
		binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
		_, _ = os.Stdout.Write(append(header[:], data...))
	}

	if mode == "end" {
		writeFrame(streamFrameEnd, nil)
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}

	// Echo data frames; answer a FIN with a FIN; EOF on stdin ends the stream.
	for {
		var frame [5]byte
		if _, err := io.ReadFull(os.Stdin, frame[:]); err != nil {
			writeFrame(streamFrameEnd, nil)
			os.Exit(0)
		}

		size := binary.BigEndian.Uint32(frame[1:])

		switch frame[0] {
		case streamFrameData:
			data := make([]byte, size)
			if _, err := io.ReadFull(os.Stdin, data); err != nil {
				os.Exit(3)
			}

			writeFrame(streamFrameData, data)
		case streamFrameFin:
			writeFrame(streamFrameFin, nil)
		default:
			os.Exit(3)
		}
	}
}

type fakeProxyLauncher struct {
	fakeLauncher
	mode string
}

func (f *fakeProxyLauncher) command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	f.calls = append(f.calls, args)

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFakeProxyHelperctl$")
	cmd.Env = append(os.Environ(), "EGRESSLAB_FAKE_PROXY="+f.mode)

	return cmd, nil
}

func proxyCapability() control.LabCapability {
	return control.LabCapability{Claims: control.LabClaims{Version: 1, Intent: control.LabIntent{
		Operation: control.LabOpenProxyStreamOp, ProfileID: testProfile, Namespace: testNamespace,
		DestinationIPv4: "93.184.216.34", DestinationPort: 443,
	}}}
}

func TestProxyStreamTransport(t *testing.T) {
	launcher := &fakeProxyLauncher{mode: "ok"}
	transport := &commandTransport{l: launcher}

	stream, err := transport.OpenProxyStream(context.Background(), proxyCapability())
	if err != nil {
		t.Fatal(err)
	}

	if stream.BoundAddr().String() != "10.0.0.2:40000" || len(launcher.calls) != 1 || launcher.calls[0][0] != "proxy-stream" {
		t.Fatalf("unexpected stream: %v %v", stream.BoundAddr(), launcher.calls)
	}

	// More than one frame, binary-clean.
	data := bytes.Repeat([]byte{0, 1, 2, 0xff, 'D', 'F'}, 20000)

	go func() { _, _ = stream.Write(data) }()

	echoed := make([]byte, len(data))
	if _, err := io.ReadFull(stream, echoed); err != nil || !bytes.Equal(echoed, data) {
		t.Fatalf("stream not binary-clean: %v", err)
	}

	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	// The destination's FIN reads as EOF, but the stream has not ended.
	if n, err := stream.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("FIN not relayed: %d %v", n, err)
	}

	select {
	case <-stream.Done():
		t.Fatal("a FIN ended the stream")
	default:
	}

	started := time.Now()
	if err := stream.Close(); err != nil || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("close did not return at once: %v", err)
	}

	select {
	case <-stream.exited:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not end the process promptly")
	}

	// It may exit on the closed stdout (SIGPIPE) while writing its END; it must exit either way.
	if stream.cmd.ProcessState == nil {
		t.Fatal("helperctl did not exit on EOF")
	}

	select {
	case <-stream.Done():
	default:
		t.Fatal("a closed stream is not done")
	}
}

// An END from helperctl ends the stream for the SOCKS client at once.
func TestProxyStreamTransportEnd(t *testing.T) {
	stream, err := (&commandTransport{l: &fakeProxyLauncher{mode: "end"}}).OpenProxyStream(context.Background(),
		proxyCapability())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if n, err := stream.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("END not read as EOF: %d %v", n, err)
	}

	select {
	case <-stream.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("END did not end the stream")
	}
}

func TestProxyStreamTransportRefusals(t *testing.T) {
	t.Run("not a stream capability", func(t *testing.T) {
		launcher := &fakeProxyLauncher{mode: "ok"}
		capability := proxyCapability()
		capability.Claims.Intent.Operation = control.LabRevokeEgressLeaseOp

		if _, err := (&commandTransport{l: launcher}).OpenProxyStream(context.Background(), capability); ErrorCode(err) != CodeInvalidRequest ||
			len(launcher.calls) != 0 {
			t.Fatalf("unexpected result: %v", err)
		}
	})

	t.Run("helper refused", func(t *testing.T) {
		_, err := (&commandTransport{l: &fakeProxyLauncher{mode: "refuse"}}).OpenProxyStream(context.Background(),
			proxyCapability())
		if ErrorCode(err) != CodeAuthorizationDenied {
			t.Fatalf("unexpected result: %v", err)
		}
	})

	t.Run("invalid acknowledgement", func(t *testing.T) {
		if _, err := (&commandTransport{l: &fakeProxyLauncher{mode: "garbage"}}).OpenProxyStream(context.Background(),
			proxyCapability()); err == nil {
			t.Fatal("invalid acknowledgement accepted")
		}
	})

	t.Run("cancelled before the acknowledgement", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()

		started := time.Now()

		_, err := (&commandTransport{l: &fakeProxyLauncher{mode: "silent"}}).OpenProxyStream(ctx, proxyCapability())
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 5*time.Second {
			t.Fatalf("unexpected result: %v after %v", err, time.Since(started))
		}
	})
}
