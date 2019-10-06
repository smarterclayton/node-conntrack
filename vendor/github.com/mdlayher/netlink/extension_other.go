// +build !linux

package netlink

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
func (c *Conn) SetReadBufferForce(bytes int) error {
	return notSupported("set-read-buffer")
}
