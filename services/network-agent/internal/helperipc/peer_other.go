//go:build !linux

package helperipc

import (
	"errors"
	"net"
)

func verifyProductionPeer(net.Conn) error {
	return errors.New("helper peer verification requires Linux")
}
