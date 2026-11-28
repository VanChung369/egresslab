package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
	"github.com/VanChung369/egresslab/services/controller/internal/labruntime"
)

func shortRecoveryTimings(t *testing.T) {
	t.Helper()

	poll, backoff, maxBackoff, gap, releaseGap := recoveryPoll, recoveryBackoff, recoveryMaxBackoff, recoveryProbeGap,
		recoveryReleaseGap
	recoveryPoll, recoveryBackoff, recoveryMaxBackoff, recoveryProbeGap, recoveryReleaseGap = 10*time.Millisecond,
		10*time.Millisecond, 20*time.Millisecond, time.Millisecond, 30*time.Millisecond

	t.Cleanup(func() {
		recoveryPoll, recoveryBackoff, recoveryMaxBackoff, recoveryProbeGap, recoveryReleaseGap = poll, backoff,
			maxBackoff, gap, releaseGap
	})
}

// newRecoveringEndpoint serves an endpoint with policy; the second poll after start faults its lab
// and runs then, in the supervisor's goroutine: what then records is read only after the endpoint
// ended or stopped.
func newRecoveringEndpoint(t *testing.T, policy recoveryPolicy, then func(rt *fakeRuntime)) (*endpointHarness, *runningEndpoint) {
	t.Helper()
	shortRecoveryTimings(t)

	e := newEndpointHarness(t)
	e.policy = policy

	start := e.rt.listCalls
	e.rt.onListLabs = func(call int) {
		if call == start+2 {
			e.rt.fault(e.profile.ID)

			if then != nil {
				then(e.rt)
			}
		}
	}

	return e, e.serve(t)
}

// heldReservations lists the holds; a running endpoint may hold the journal's lock for a moment.
func heldReservations(t *testing.T, h *harness) []control.EgressReservation {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		err := h.run("list-reservations")
		if err == nil {
			var listed reservationListResult
			if err := json.Unmarshal(h.out.Bytes(), &listed); err != nil {
				t.Fatal(err)
			}

			return listed.Reservations
		}

		if labruntime.ErrorCode(err) != codeReservationBusy || time.Now().After(deadline) {
			t.Fatal(err)
		}
	}
}

func waitForNewHold(t *testing.T, h *harness, old string) control.EgressReservation {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if holds := heldReservations(t, h); len(holds) == 1 && holds[0].ID != old {
			return holds[0]
		}

		// Not faster: each read takes the journal's lock, which a release then finds busy.
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("no new hold")

	return control.EgressReservation{}
}

func waitForEnd(t *testing.T, running *runningEndpoint) error {
	t.Helper()

	select {
	case err := <-running.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the endpoint did not stop")
		return nil
	}
}

// reportOtherAddress makes rt's tunnels come back at another address, on top of the fixture's
// clock stamps.
func reportOtherAddress(rt *fakeRuntime) {
	stamp := rt.multiProbeEdit
	ip := netip.MustParseAddr("8.8.8.8")

	rt.multiProbeEdit = func(info *control.LabMultiProbeInfo) {
		stamp(info)
		info.IPv4 = ip

		for i := range info.Sources {
			info.Sources[i].IPv4 = ip
		}
	}
}

// connectReplaced connects until the replaced route is served; the hold is in the journal shortly
// before the endpoint swaps to it.
func connectReplaced(t *testing.T, running *runningEndpoint) byte {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if code := running.connect(t); code != 2 || time.Now().After(deadline) {
			return code
		}
	}
}

// A fault is replaced by a new hold at the same address, and the endpoint mints for the new hold.
func TestServeEndpointRecoversAFault(t *testing.T) {
	e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, sameIP: true, attempts: 3}, nil)

	hold := waitForNewHold(t, e.harness, running.ReservationID)

	if code := connectReplaced(t, running); code != 1 {
		t.Fatalf("CONNECT after the recovery answered %d", code)
	}

	if err := running.stop(); err != nil {
		t.Fatal(err)
	}

	streams := e.rt.streamCalls
	if hold.IPv4.String() != "8.8.4.4" || len(streams) == 0 ||
		streams[len(streams)-1].Claims.Intent.ReservationID != hold.ID || len(e.rt.revokeCalls) != 1 ||
		!slices.Contains(e.rt.calls, "DeleteLab") || e.rt.labs[e.profile.ID] != labNS || e.rt.faulted[e.profile.ID] {
		t.Fatalf("incorrect recovery: hold %s, streams %d, calls %v", hold.ID, len(streams), e.rt.calls)
	}
}

// While the route is replaced, every CONNECT is refused, from the fault on, while the old hold is
// still in the journal and after it is released; afterwards they are minted again.
func TestServeEndpointRefusesDuringRecovery(t *testing.T) {
	for _, step := range []string{control.LabRevokeEgressLeaseOp, "StageInfo"} {
		t.Run(step, func(t *testing.T) {
			reached, resume := make(chan struct{}), make(chan struct{})

			var once sync.Once

			e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, sameIP: true, attempts: 3}, func(rt *fakeRuntime) {
				rt.onRecord = func(op string) {
					if op == step {
						once.Do(func() {
							close(reached)
							<-resume
						})
					}
				}
			})

			select {
			case <-reached:
			case <-time.After(10 * time.Second):
				t.Fatal("the recovery did not reach " + step)
			}

			if code := running.connect(t); code != 2 {
				t.Fatalf("CONNECT during the recovery answered %d", code)
			}

			close(resume)
			waitForNewHold(t, e.harness, running.ReservationID)

			if code := connectReplaced(t, running); code != 1 {
				t.Fatalf("CONNECT after the recovery answered %d", code)
			}

			if err := running.stop(); err != nil {
				t.Fatal(err)
			}

			// The CONNECT after the recovery reached the transport, minted for the new hold.
			holds := heldReservations(t, e.harness)
			streams := e.rt.streamCalls

			if len(holds) != 1 || len(streams) == 0 || streams[len(streams)-1].Claims.Intent.ReservationID != holds[0].ID {
				t.Fatal("the CONNECT after the recovery did not use the new hold")
			}
		})
	}
}

// Under the same-address policy, a tunnel that comes back elsewhere makes no hold; after its attempts
// the endpoint stops and leaves no lab.
func TestServeEndpointRecoveryKeepsTheAddress(t *testing.T) {
	var candidates int

	e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, sameIP: true, attempts: 2}, func(rt *fakeRuntime) {
		candidates = len(rt.candidateCalls)
		reportOtherAddress(rt)
	})

	if err := waitForEnd(t, running); !errors.Is(err, errRecoveryExceeded) {
		t.Fatalf("endpoint ended with %v", err)
	}

	if holds := heldReservations(t, e.harness); len(holds) != 0 || len(e.rt.candidateCalls) != candidates ||
		len(e.rt.multiProbeCalls) < 2 || e.rt.labs[e.profile.ID] != "" {
		t.Fatalf("holds %d, candidates %d, lab %q", len(holds), len(e.rt.candidateCalls), e.rt.labs[e.profile.ID])
	}
}

// With any address approved, the new address is reserved.
func TestServeEndpointRecoveryAnyAddress(t *testing.T) {
	e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, attempts: 1}, func(rt *fakeRuntime) {
		reportOtherAddress(rt)
	})

	hold := waitForNewHold(t, e.harness, running.ReservationID)

	if err := running.stop(); err != nil {
		t.Fatal(err)
	}

	if hold.IPv4.String() != "8.8.8.8" {
		t.Fatalf("reserved %s", hold.IPv4)
	}
}

// A release that does not confirm the old generation's retirement stops the endpoint: nothing is
// rebuilt and the hold stays.
func TestServeEndpointRecoveryStopsOnFailedRelease(t *testing.T) {
	var created int

	e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, sameIP: true, attempts: 3}, func(rt *fakeRuntime) {
		created = len(rt.created)
		rt.revokeErr = labruntime.Errorf(labruntime.CodeStateUncertain, "revocation unconfirmed")
	})

	if err := waitForEnd(t, running); err == nil || !strings.Contains(err.Error(), "release of the faulted hold") {
		t.Fatalf("endpoint ended with %v", err)
	}

	if holds := heldReservations(t, e.harness); len(holds) != 1 || holds[0].ID != running.ReservationID ||
		len(e.rt.created) != created {
		t.Fatal("a failed release went on with the recovery")
	}
}

// Anything but a fault of the served lab stops the endpoint without touching the hold: a lab that is
// gone, another helper epoch, or a lab another way than faulted.
func TestServeEndpointStopsWithoutAFault(t *testing.T) {
	for _, tt := range []struct {
		mode   string
		change func(e *endpointHarness)
		want   string
	}{
		{mode: "lab gone", change: func(e *endpointHarness) { delete(e.rt.labs, e.profile.ID) }, want: "gone"},
		{mode: "other helper", change: func(e *endpointHarness) {
			e.rt.mu.Lock()
			e.rt.info.HelperID = epoch2
			e.rt.mu.Unlock()
		}, want: "recover-egress"},
		{mode: "disconnected", change: func(e *endpointHarness) { e.rt.retireTunnel(e.profile.ID) }, want: "sealed"},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			shortRecoveryTimings(t)

			e := newEndpointHarness(t)
			e.policy = recoveryPolicy{enabled: true, sameIP: true, attempts: 3}

			start := e.rt.listCalls
			e.rt.onListLabs = func(call int) {
				if call == start+1 {
					tt.change(e)
				}
			}

			running := e.serve(t)

			if err := waitForEnd(t, running); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("endpoint ended with %v", err)
			}

			if holds := heldReservations(t, e.harness); len(holds) != 1 || len(e.rt.revokeCalls) != 0 {
				t.Fatal("the endpoint released or lost the hold")
			}
		})
	}
}

// The recovery flags belong to serve-endpoint, the tuning ones need -recover, and both are checked.
func TestRecoveryFlags(t *testing.T) {
	h := newHarness(t)
	endpoint := "proxy_0123456789abcdef"

	for _, args := range [][]string{
		{"-approve", "-recover", "create-lab", h.profile.ID},
		{"-approve", "-recover=false", "create-lab", h.profile.ID},
		{"-approve", "-recover-ip", "any", "serve-endpoint", endpoint},
		{"-approve", "-recover", "-recover-ip", "nearby", "serve-endpoint", endpoint},
		{"-approve", "-recover", "-recover-attempts", "0", "serve-endpoint", endpoint},
		{"-approve", "-recover", "-recover-attempts", "21", "serve-endpoint", endpoint},
	} {
		if err := h.run(args...); err == nil || !strings.Contains(err.Error(), "recover") {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// A release that release-egress documents as "confirm with a new release" is asked again, a bounded
// number of times; any other refusal is not.
func TestServeEndpointRecoveryConfirmsTheRelease(t *testing.T) {
	for _, tt := range []struct {
		code    string
		failing int
		ok      bool
	}{
		{codeReservationReleaseUnconfirmed, 2, true},
		{codeReservationBusy, 1, true},
		{codeLeaseRevocationUnconfirmed, 3, true},
		{codeReservationReleaseUnconfirmed, recoveryReleases, false},
		{labruntime.CodeAuthorizationDenied, 1, false},
	} {
		t.Run(fmt.Sprintf("%s x%d", tt.code, tt.failing), func(t *testing.T) {
			saved := releaseHold
			t.Cleanup(func() { releaseHold = saved })

			calls := 0
			releaseHold = func(s *session, id string, recovering bool) (reservationReleaseCommandResult, error) {
				if calls++; calls <= tt.failing {
					return reservationReleaseCommandResult{}, labruntime.Errorf(tt.code, "simulated")
				}

				return saved(s, id, recovering)
			}

			e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, sameIP: true, attempts: 1}, nil)

			if !tt.ok {
				if err := waitForEnd(t, running); err == nil || !strings.Contains(err.Error(), tt.code) {
					t.Fatalf("endpoint ended with %v", err)
				}

				if want := map[bool]int{true: recoveryReleases, false: 1}[releaseAgain[tt.code]]; calls != want {
					t.Fatalf("release asked %d times, want %d", calls, want)
				}

				return
			}

			waitForNewHold(t, e.harness, running.ReservationID)

			// At least: the test's own reads of the journal can keep a real release busy too.
			if err := running.stop(); err != nil || calls < tt.failing+1 {
				t.Fatalf("release calls %d: %v", calls, err)
			}
		})
	}
}

// An uncertain outcome during an attempt stops the endpoint at once, whatever attempts are left, and
// leaves the lab for an operator.
func TestServeEndpointRecoveryStopsWhenUncertain(t *testing.T) {
	var created int

	e, running := newRecoveringEndpoint(t, recoveryPolicy{enabled: true, sameIP: true, attempts: 3}, func(rt *fakeRuntime) {
		created = len(rt.created)
		rt.multiProbeErr = labruntime.Errorf(labruntime.CodeStateUncertain, "tunnel state unknown")
	})

	if err := waitForEnd(t, running); labruntime.ErrorCode(err) != labruntime.CodeStateUncertain {
		t.Fatalf("endpoint ended with %v", err)
	}

	if len(e.rt.created) != created+1 || e.rt.labs[e.profile.ID] == "" {
		t.Fatalf("labs created %d, lab %q", len(e.rt.created)-created, e.rt.labs[e.profile.ID])
	}
}

// With no attempt left, a later fault stops the endpoint without releasing or deleting anything.
func TestServeEndpointRecoveryBudgetLeavesTheNextFault(t *testing.T) {
	shortRecoveryTimings(t)

	e := newEndpointHarness(t)
	e.policy = recoveryPolicy{enabled: true, sameIP: true, attempts: 1}

	start := e.rt.listCalls
	faults := 0
	e.rt.onListLabs = func(call int) {
		// The first fault early; the second once the first recovery's hold is prepared.
		if (call == start+2 && faults == 0) || (faults == 1 && len(e.rt.prepareCalls) == 2) {
			faults++
			e.rt.fault(e.profile.ID)
		}
	}

	running := e.serve(t)

	if err := waitForEnd(t, running); !errors.Is(err, errRecoveryExceeded) {
		t.Fatalf("endpoint ended with %v", err)
	}

	holds := heldReservations(t, e.harness)
	if faults != 2 || len(e.rt.revokeCalls) != 1 || len(holds) != 1 || holds[0].ID == running.ReservationID ||
		!e.rt.faulted[e.profile.ID] {
		t.Fatalf("faults %d, releases %d, holds %d", faults, len(e.rt.revokeCalls), len(holds))
	}
}

// A helper restart, or the endpoint deleted, during a recovery stops it before a new lab is made. (A
// restart before the release already fails the release, which needs the original epoch.)
func TestServeEndpointRecoveryNeedsTheSameHelperAndEndpoint(t *testing.T) {
	for _, tt := range []struct {
		mode   string
		change func(e *endpointHarness)
		want   string
	}{
		{mode: "helper restarted", change: func(e *endpointHarness) {
			e.rt.mu.Lock()
			e.rt.info.HelperID = epoch2
			e.rt.mu.Unlock()
		}, want: "helper changed"},
		{mode: "endpoint deleted", change: func(e *endpointHarness) {
			if err := e.store.DeleteEndpoint(e.endpoint.ID); err != nil {
				t.Error(err)
			}
		}, want: "endpoint"},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			shortRecoveryTimings(t)

			e := newEndpointHarness(t)
			e.policy = recoveryPolicy{enabled: true, sameIP: true, attempts: 3}

			// All set before serving: the hooks run in the supervisor's goroutine.
			var created int

			start := e.rt.listCalls
			e.rt.onListLabs = func(call int) {
				if call == start+2 {
					created = len(e.rt.created)
					e.rt.fault(e.profile.ID)

					// After the release, while the faulted lab is deleted: before the new lab.
					e.rt.onRecord = func(op string) {
						if op == "DeleteLab" {
							tt.change(e)
						}
					}
				}
			}

			running := e.serve(t)

			if err := waitForEnd(t, running); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("endpoint ended with %v", err)
			}

			if len(e.rt.created) != created {
				t.Fatal("a lab was made after the change")
			}
		})
	}
}

// A lab a failed attempt left is not deleted once a hold for the profile exists: that lab may carry
// another process's reservation.
func TestRecoveryLeavesALabWithAHold(t *testing.T) {
	e := newEndpointHarness(t)

	authority, _, err := (&session{d: e.deps(), dataDir: e.dir}).openReservationAuthority()
	if err != nil {
		t.Fatal(err)
	}

	s := &session{d: e.deps(), dataDir: e.dir, provider: e.rt}

	err = s.dropLeftover(context.Background(), authority, e.profile.ID, labNS)

	var stop *recoveryStop
	if !errors.As(err, &stop) || !strings.Contains(err.Error(), "hold for the profile exists") || e.rt.labs[e.profile.ID] != labNS {
		t.Fatalf("leftover with a hold: %v", err)
	}
}
