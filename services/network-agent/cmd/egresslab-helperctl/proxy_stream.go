package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/VanChung369/egresslab/services/network-agent/internal/helperauth"
	"github.com/VanChung369/egresslab/services/network-agent/internal/helperipc"
)

// Stream frames in both directions after the capability and the ack: a type byte and a big-endian
// length. Neither a killed launcher nor a closed stdout reaches the other side through limactl, so
// every end is explicit. From the controller: data, FIN (the client is done sending) and EOF (close).
// To the controller: data, FIN (the destination is done sending; the upload goes on) and END.
const (
	streamFrameData = 'D'
	streamFrameFin  = 'F'
	streamFrameEnd  = 'E'

	maxStreamFrameBytes = 32 * 1024
)

// runProxyStream reads the capability frame, opens the stream, writes the helper's ack frame and
// then relays: stdout carries only raw stream bytes after the ack, never a JSON failure.
func runProxyStream(stdin io.Reader, stdout io.Writer) error {
	capability, err := readCapabilityFrame(stdin)
	if err != nil {
		writeAckFrame(stdout, helperipc.ProxyStreamAck{
			Version: helperipc.Version, Operation: helperauth.OpOpenProxyStream, Code: helperipc.CodeInvalidRequest,
		})

		return err
	}

	conn, ack, err := helperipc.OpenProxyStream(context.Background(), socketPath, capability)
	if err != nil {
		if ack.Operation == "" {
			ack = helperipc.ProxyStreamAck{
				Version: helperipc.Version, Operation: helperauth.OpOpenProxyStream, Code: helperipc.ErrorCode(err),
			}
		}

		writeAckFrame(stdout, ack)

		return err
	}
	defer conn.Close()

	if err := helperipc.WriteFrame(stdout, ack); err != nil {
		return err
	}

	var outMu sync.Mutex

	writeOut := func(kind byte, data []byte) error {
		outMu.Lock()
		defer outMu.Unlock()

		header := [5]byte{kind}
		binary.BigEndian.PutUint32(header[1:], uint32(len(data)))

		if _, err := stdout.Write(header[:]); err != nil {
			return err
		}

		_, err := stdout.Write(data)

		return err
	}

	var endOnce sync.Once
	end := func() { endOnce.Do(func() { _ = writeOut(streamFrameEnd, nil) }) }

	downstream := make(chan struct{})

	go func() {
		defer close(downstream)

		buf := make([]byte, maxStreamFrameBytes)

		for {
			n, err := conn.Read(buf)
			if n > 0 && writeOut(streamFrameData, buf[:n]) != nil {
				_ = conn.Close()
				return
			}

			if errors.Is(err, io.EOF) {
				_ = writeOut(streamFrameFin, nil)
				return
			}

			if err != nil {
				end()
				_ = conn.Close()

				return
			}
		}
	}()

	// The stream lives until the controller closes stdin or the helper refuses an upload.
	relayStreamFrames(stdin, conn)
	<-downstream
	end()

	return nil
}

func writeAckFrame(w io.Writer, ack helperipc.ProxyStreamAck) {
	if ack.Code == "" {
		ack.Code = helperipc.CodeInternal
	}

	_ = helperipc.WriteFrame(w, ack)
}

func readCapabilityFrame(r io.Reader) (helperauth.SignedCapability, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return helperauth.SignedCapability{}, invalid("missing capability frame")
	}

	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxCapabilityBytes {
		return helperauth.SignedCapability{}, invalid("invalid capability frame")
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return helperauth.SignedCapability{}, invalid("truncated capability frame")
	}

	var capability helperauth.SignedCapability

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&capability); err != nil || decoder.More() {
		return helperauth.SignedCapability{}, invalid("invalid capability JSON")
	}

	if !helperauth.ValidOpenProxyStreamIntent(capability.Claims.Intent) {
		return helperauth.SignedCapability{}, invalid("not a proxy stream capability")
	}

	return capability, nil
}

// relayStreamFrames writes data frames to the helper, half-closes on FIN and closes on CLOSE, EOF or
// any malformed frame.
func relayStreamFrames(r io.Reader, conn *net.UnixConn) {
	defer conn.Close()

	buf := make([]byte, maxStreamFrameBytes)

	for {
		var header [5]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return
		}

		size := binary.BigEndian.Uint32(header[1:])

		switch header[0] {
		case streamFrameData:
			if size == 0 || size > maxStreamFrameBytes {
				return
			}

			if _, err := io.ReadFull(r, buf[:size]); err != nil {
				return
			}

			if _, err := conn.Write(buf[:size]); err != nil {
				return
			}

		case streamFrameFin:
			if size != 0 || conn.CloseWrite() != nil {
				return
			}

		default:
			return
		}
	}
}
