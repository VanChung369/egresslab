package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	isolationVerifyTimeout = 8 * time.Second
	quarantineTimeout      = 12 * time.Second
)

// Quarantine removes the tunnel of an owned, tracked lab namespace. Disconnect deletes wg0
// before the host-side underlay table; if that fails, wg0 is forced down as a fallback (which
// also closes its encrypted socket) and the underlay table is kept.
//
// It never brings a tunnel back. Any error means the caller must not assume isolation has
// been restored.
func (l *VPNEgressLab) Quarantine(ctx context.Context, namespace string) error {
	if l == nil || l.manager == nil || !labNamePattern.MatchString(namespace) {
		return errors.New("invalid VPN quarantine request")
	}

	l.manager.mu.Lock()
	_, owned := l.manager.owned[namespace]
	_, tracked := l.underlay[namespace]
	l.manager.mu.Unlock()

	if !owned || !tracked {
		return fmt.Errorf("cannot quarantine an unowned or untracked tunnel %s", namespace)
	}

	err := l.Disconnect(ctx, namespace)
	if err == nil {
		return nil
	}

	// Emergency fallback, on its own deadline so an expired ctx cannot skip it.
	downCtx, cancel := context.WithTimeout(context.Background(), netNSCommandTimeout)
	downErr := l.ip(downCtx, "-n", namespace, "link", "set", labWGInterface, "down")
	cancel()

	if downErr != nil {
		return errors.Join(
			fmt.Errorf("disconnect tunnel: %w", err),
			fmt.Errorf("emergency interface down: %w", downErr),
		)
	}

	return fmt.Errorf("disconnect incomplete (wg0 was forced down; inspect manually): %w", err)
}

// WatchIsolation polls the namespace firewall, the host-side underlay table and wg0's fwmark
// for the manual VPN egress lab.
//
// On a failed or unverifiable check it quarantines the tunnel, sends one error and closes the
// channel. Cancelling ctx closes the channel without an error.
//
// Polling cannot catch a change instantly: traffic can flow between two checks. This raises
// detection and reaction in the lab; it is not a process-independent kill switch.
func (l *VPNEgressLab) WatchIsolation(ctx context.Context, namespace string, interval time.Duration) <-chan error {
	result := make(chan error, 1)

	go func() {
		defer close(result)

		if l == nil || l.firewall == nil || !labNamePattern.MatchString(namespace) || interval <= 0 {
			result <- errors.New("invalid VPN isolation monitor configuration")
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			if ctx.Err() != nil {
				return
			}

			verifyCtx, cancel := context.WithTimeout(ctx, isolationVerifyTimeout)
			err := l.verifyProbeIsolation(verifyCtx, namespace)
			cancel()

			// A check cut short by cancellation is not evidence of drift.
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), quarantineTimeout)
				quarantineErr := l.Quarantine(cleanupCtx, namespace)
				cleanupCancel()

				if quarantineErr != nil {
					result <- errors.Join(err, fmt.Errorf("emergency quarantine failed: %w", quarantineErr))
				} else {
					result <- fmt.Errorf("isolation drift detected; tunnel quarantined: %w", err)
				}

				return
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return result
}
