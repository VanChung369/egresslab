package helperipc

import (
	"context"
	"errors"
	"testing"
	"time"
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

// A waiting request learns the keeper's reason; a keeper still stopping at the deadline is uncertain.
func TestProxyPlaneFailure(t *testing.T) {
	plane := newProxyPlane(context.Background(), "profile", "reservation")
	plane.close(errLabAuthorization)

	if err := plane.failure(time.Now().Add(100 * time.Millisecond)); !errors.Is(err, errLabUncertain) {
		t.Fatalf("a stopping keeper reported %v", err)
	}

	plane.stopKeeper(errLabFaulted)

	if err := plane.failure(time.Now().Add(time.Second)); !errors.Is(err, errLabFaulted) {
		t.Fatalf("the keeper's reason was lost: %v", err)
	}
}
