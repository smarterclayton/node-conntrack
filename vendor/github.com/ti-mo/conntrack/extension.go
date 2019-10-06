package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"github.com/ti-mo/netfilter"
)

type AttributeType = attributeType
type EventType = eventType

const (
	CTATupleOrig = ctaTupleOrig
	CTAStatus    = ctaStatus
)

func (et *eventType) Unmarshal(h netfilter.Header) error {
	return et.unmarshal(h)
}

func (s *Status) Unmarshal(h netfilter.Attribute) error {
	return s.unmarshal(h)
}

func (t *Tuple) Unmarshal(h netfilter.Attribute) error {
	return t.unmarshal(h)
}

func (e *Event) Unmarshal(msg netlink.Message) error {
	return e.unmarshal(msg)
}

func (f *Flow) Unmarshal(attrs []netfilter.Attribute) error {
	return f.unmarshal(attrs)
}

// SetReadBuffer updates the buffer size of the connection or
// returns an error.
func (c *Conn) SetReadBuffer(bufSize int) error {
	return c.conn.SetReadBuffer(bufSize)
}

// SetReadBufferForce updates the buffer size of the connection or
// returns an error.
func (c *Conn) SetReadBufferForce(bufSize int) error {
	return c.conn.SetReadBufferForce(bufSize)
}

// ListenRaw joins the Netfilter connection to a multicast group and starts a given
// amount of Flow decoders from the Conn to the Flow channel. Returns an error channel
// the workers will return any errors on. Any error during Flow decoding is fatal and
// will halt the worker it occurs on. When numWorkers amount of errors have been received on
// the error channel, no more events will be produced on evChan.
//
// The Conn will be marked as having listeners active, which will prevent Listen from being
// called again. For listening on other groups, open another socket.
//
// filterFn is invoked once per received message. If the function returns an error the
// worker stops.
func (c *Conn) ListenRaw(numWorkers uint8, groups []netfilter.NetlinkGroup, filterFn func(recv []netlink.Message) error) (chan error, error) {

	if numWorkers == 0 {
		return nil, errors.Errorf(errWorkerCount, numWorkers)
	}

	// Prevent Listen() from being called twice on the same Conn.
	// This is checked again in JoinGroups(), but an early failure is preferred.
	if c.conn.IsMulticast() {
		return nil, errConnHasListeners
	}

	err := c.conn.JoinGroups(groups)
	if err != nil {
		return nil, err
	}

	errChan := make(chan error)

	// Start numWorkers amount of worker goroutines
	for id := uint8(0); id < numWorkers; id++ {
		go c.eventWorkerRaw(id, errChan, filterFn)
	}

	return errChan, nil
}

// eventWorkerRaw is a worker function that decodes multicast messages from the underlying socket.
func (c *Conn) eventWorkerRaw(workerID uint8, errChan chan<- error, filterFn func([]netlink.Message) error) {
	for {
		// Receive data from the Netlink socket
		recv, err := c.conn.Receive()
		if err != nil {
			errChan <- errors.Wrap(err, fmt.Sprintf(errWorkerReceive, workerID))
			return
		}

		// Receive() always returns a list of Netlink Messages, but multicast messages should never be multi-part
		if len(recv) > 1 {
			errChan <- errMultipartEvent
			return
		}
		if err := filterFn(recv); err != nil {
			errChan <- err
			return
		}
	}
}
