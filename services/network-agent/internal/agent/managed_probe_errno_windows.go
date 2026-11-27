package agent

import "syscall"

// Winsock reports its own codes, and syscall maps none of them to the Unix names, nor counts
// WSAETIMEDOUT as a timeout. A read after an abrupt disconnect can also end in ERROR_NETNAME_DELETED.
var (
	probeResetErrnos = []error{syscall.WSAECONNRESET, syscall.WSAECONNABORTED, syscall.ERROR_NETNAME_DELETED}
	probeLostErrnos  = append([]error{
		syscall.Errno(10061), // WSAECONNREFUSED
		syscall.Errno(10065), // WSAEHOSTUNREACH
		syscall.Errno(10051), // WSAENETUNREACH
		syscall.Errno(10060), // WSAETIMEDOUT
	}, probeResetErrnos...)
)
