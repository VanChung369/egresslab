//go:build linux

package helperipc

import (
	"errors"
	"net"
)

// verifyProductionPeer checks that the production socket is served by root, before a capability
// is sent. A helper under a dedicated service UID will need that UID here instead.
func verifyProductionPeer(conn net.Conn) error {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("expected Unix socket")
	}

	uid, err := peerUID(unix)
	if err != nil {
		return errors.New("cannot verify helper credentials")
	}

	if uid != 0 {
		return errors.New("unexpected helper UID")
	}

	return nil
}
