package labruntime

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

// Stream frames in both directions after the capability and the ack: a type byte and a big-endian
// length. Neither a killed launcher nor a closed stdout crosses limactl, so every end is explicit.
// To helperctl: data, FIN (the client is done sending) and EOF on stdin (close). From helperctl: data,
// FIN (the destination is done sending; the upload goes on) and END.
const (
	streamFrameData = 'D'
	streamFrameFin  = 'F'
	streamFrameEnd  = 'E'

	maxStreamFrameBytes  = 32 * 1024
	maxCapabilityBytes   = 8192
	proxyStreamHandshake = 70 * time.Second
	proxyStreamCloseWait = 3 * time.Second
)

// ProxyStreamTransport opens one signed proxy stream; it is kept apart from HelperTransport.
type ProxyStreamTransport interface {
	OpenProxyStream(ctx context.Context, capability control.LabCapability) (*ProxyStream, error)
}

var _ ProxyStreamTransport = (*commandTransport)(nil)

type proxyStreamAck struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	OK        bool   `json:"ok"`
	Code      string `json:"code,omitempty"`

	BoundIPv4 string `json:"bound_ipv4,omitempty"`
	BoundPort uint16 `json:"bound_port,omitempty"`
}

// ProxyStream is one helperctl process relaying one TCP stream of the runtime.
type ProxyStream struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *limitedBuffer
	bound  netip.AddrPort

	writeMu   sync.Mutex
	closeOnce sync.Once

	pending []byte // the rest of the current data frame
	readEnd bool
	done    chan struct{}
	endOnce sync.Once
	exited  chan struct{} // closed once the process has been reaped
}

// OpenProxyStream starts helperctl's streaming mode, sends the capability and waits for the helper's
// acknowledgement. It never retries and never dials anything itself.
func (t *commandTransport) OpenProxyStream(ctx context.Context, capability control.LabCapability) (*ProxyStream, error) {
	intent := capability.Claims.Intent
	if intent.Operation != control.LabOpenProxyStreamOp || intent.DestinationIPv4 == "" || intent.DestinationPort == 0 {
		return nil, Errorf(CodeInvalidRequest, "invalid proxy stream capability")
	}

	payload, err := json.Marshal(capability)
	if err != nil {
		return nil, err
	}
	defer clear(payload)

	if len(payload) > maxCapabilityBytes {
		return nil, Errorf(CodeInvalidRequest, "proxy stream capability too large")
	}

	streamCtx, cancel := context.WithCancel(ctx)

	cmd, err := t.l.command(streamCtx, "proxy-stream")
	if err != nil {
		cancel()
		return nil, err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}

	stderr := &limitedBuffer{limit: maxStderrBytes}
	cmd.Stderr = stderr
	cmd.WaitDelay = proxyStreamCloseWait

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, Errorf(CodeRuntimeUnavailable, t.l.name()+": helperctl proxy-stream failed to start: "+err.Error())
	}

	stream := &ProxyStream{cmd: cmd, cancel: cancel, stdin: stdin, stdout: stdout, stderr: stderr,
		done: make(chan struct{}), exited: make(chan struct{})}

	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	defer clear(frame)

	if _, err := stdin.Write(frame); err != nil {
		_ = stream.Close()
		return nil, Errorf(CodeRuntimeUnavailable, "proxy stream request not delivered")
	}

	ack, err := stream.readAck(ctx)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}

	if !ack.OK {
		_ = stream.Close()

		code := ack.Code
		if !helperCodes[code] {
			code = CodeInternal
		}

		return nil, Errorf(code, "helper refused the proxy stream")
	}

	bound, err := netip.ParseAddr(ack.BoundIPv4)
	if err != nil || !bound.Is4() || bound.String() != ack.BoundIPv4 || ack.BoundPort == 0 {
		_ = stream.Close()
		return nil, errors.New("invalid proxy stream acknowledgement")
	}

	stream.bound = netip.AddrPortFrom(bound, ack.BoundPort)

	return stream, nil
}

// readAck reads exactly one length-prefixed acknowledgement, so no stream byte is consumed with it.
func (s *ProxyStream) readAck(ctx context.Context) (proxyStreamAck, error) {
	type result struct {
		ack proxyStreamAck
		err error
	}

	done := make(chan result, 1)

	go func() {
		var header [4]byte
		if _, err := io.ReadFull(s.stdout, header[:]); err != nil {
			// stderr is still being written by the process; it is not read here.
			done <- result{err: Errorf(CodeRuntimeUnavailable, "no proxy stream acknowledgement")}
			return
		}

		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > maxResponseBytes {
			done <- result{err: errors.New("invalid proxy stream acknowledgement")}
			return
		}

		payload := make([]byte, size)
		if _, err := io.ReadFull(s.stdout, payload); err != nil {
			done <- result{err: errors.New("truncated proxy stream acknowledgement")}
			return
		}

		var ack proxyStreamAck

		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&ack); err != nil || decoder.More() || ack.Version != 1 ||
			ack.Operation != control.LabOpenProxyStreamOp || (ack.OK && ack.Code != "") || (!ack.OK && ack.Code == "") {
			done <- result{err: errors.New("invalid proxy stream acknowledgement")}
			return
		}

		done <- result{ack: ack}
	}()

	timer := time.NewTimer(proxyStreamHandshake)
	defer timer.Stop()

	select {
	case r := <-done:
		return r.ack, r.err
	case <-timer.C:
		return proxyStreamAck{}, Errorf(CodeRuntimeUnavailable, "proxy stream acknowledgement timed out")
	case <-ctx.Done():
		return proxyStreamAck{}, ctx.Err()
	}
}

// Read returns the destination's data; io.EOF after its FIN, and after the stream ended.
func (s *ProxyStream) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		if s.readEnd {
			return 0, io.EOF
		}

		var header [5]byte
		if _, err := io.ReadFull(s.stdout, header[:]); err != nil {
			s.readEnd = true
			s.end()

			return 0, io.EOF
		}

		size := binary.BigEndian.Uint32(header[1:])

		switch {
		case header[0] == streamFrameData && size > 0 && size <= maxStreamFrameBytes:
			s.pending = make([]byte, size)
			if _, err := io.ReadFull(s.stdout, s.pending); err != nil {
				s.pending, s.readEnd = nil, true
				s.end()

				return 0, io.EOF
			}

		case header[0] == streamFrameFin && size == 0:
			s.readEnd = true
			return 0, io.EOF

		default:
			s.readEnd = true
			s.end()

			return 0, io.EOF
		}
	}

	n := copy(p, s.pending)
	s.pending = s.pending[n:]

	return n, nil
}

func (s *ProxyStream) end() { s.endOnce.Do(func() { close(s.done) }) }

// Done is closed once the stream has ended in the runtime (an END frame, a broken pipe or Close); a
// FIN alone does not close it.
func (s *ProxyStream) Done() <-chan struct{} { return s.done }

// Write sends data frames of at most 32 KiB.
func (s *ProxyStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	written := 0

	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxStreamFrameBytes {
			chunk = chunk[:maxStreamFrameBytes]
		}

		var header [5]byte
		header[0] = streamFrameData
		binary.BigEndian.PutUint32(header[1:], uint32(len(chunk)))

		if _, err := s.stdin.Write(header[:]); err != nil {
			return written, err
		}

		if _, err := s.stdin.Write(chunk); err != nil {
			return written, err
		}

		written += len(chunk)
		p = p[len(chunk):]
	}

	return written, nil
}

// CloseWrite half-closes the stream: the destination sees the end of the client's data.
func (s *ProxyStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.stdin.Write([]byte{streamFrameFin, 0, 0, 0, 0})

	return err
}

// Close ends the stream: EOF on stdin closes it in the guest. It returns at once; the process is
// reaped in the background and killed only if it does not exit within the grace period.
func (s *ProxyStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		s.end()

		reaped := make(chan struct{})

		go func() {
			_ = s.cmd.Wait()
			close(reaped)
		}()

		go func() {
			timer := time.NewTimer(proxyStreamCloseWait)
			defer timer.Stop()

			select {
			case <-reaped:
			case <-timer.C:
				s.cancel()
				<-reaped
			}

			s.cancel()
			close(s.exited)
		}()
	})

	return nil
}

func (s *ProxyStream) BoundAddr() netip.AddrPort { return s.bound }

// Exited is closed once the runtime process has been reaped after Close: the helper has seen the
// stream end, though it may not have released the stream's slot yet.
func (s *ProxyStream) Exited() <-chan struct{} { return s.exited }
