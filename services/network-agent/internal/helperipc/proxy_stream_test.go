package helperipc

import (
	"context"
	"testing"
)

// Withdrawn requests leave no trace: the queue of a live plane never refuses a request.
func TestProxyPlaneQueue(t *testing.T) {
	plane := newProxyPlane(context.Background(), "profile", "reservation")

	request := func() *proxyRequest {
		return &proxyRequest{ctx: context.Background(), result: make(chan proxyAdmission, 1)}
	}

	for range 4 * maxProxyStreams {
		r := request()
		if !plane.submit(r) || !plane.withdraw(r) {
			t.Fatal("a live plane refused or kept a request")
		}
	}

	if !plane.idle() {
		t.Fatal("withdrawn requests still count")
	}

	r := request()
	if !plane.submit(r) || plane.next() != r || plane.withdraw(r) {
		t.Fatal("a claimed request was withdrawn")
	}

	plane.finish(r, proxyAdmission{err: errLabBusy})

	if !plane.retireIfIdle() || plane.submit(request()) {
		t.Fatal("a retired plane accepted a request")
	}
}
