// +build linux

package netlink

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func (s *sysSocket) Recvmsg(p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, 0, 0, nil, syscall.EBADF
	}

	var (
		n, oobn, recvflags int
		from               unix.Sockaddr
		err                error
	)
	if err := fdread(s.fd, func(fd int) bool {
		n, oobn, recvflags, from, err = unix.Recvmsg(fd, p, oob, flags)

		// When the socket is in non-blocking mode, we might see
		// EAGAIN and end up here. In that case, return false to
		// let the poller wait for readiness. See the source code
		// for internal/poll.FD.RawRead for more details.
		//
		// If the socket is in blocking mode, EAGAIN should never occur.
		return err != syscall.EAGAIN
	}); err != nil {
		return 0, 0, 0, nil, err
	}

	return n, oobn, recvflags, from, err
}

// A forceBufferSetter is a Socket that supports setting connection buffer sizes with the Force flag.
type forceBufferSetter interface {
	Socket
	SetReadBufferForce(bytes int) error
}

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
func (c *conn) SetReadBufferForce(bytes int) error {
	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_SOCKET,
		unix.SO_RCVBUFFORCE,
		bytes,
	))
}

// SetReadBufferForce sets the size of the operating system's receive buffer
// associated with the Conn.
func (c *Conn) SetReadBufferForce(bytes int) error {
	conn, ok := c.sock.(forceBufferSetter)
	if !ok {
		return notSupported("set-read-buffer-force")
	}

	return newOpError("set-read-buffer-force", conn.SetReadBufferForce(bytes))
}
