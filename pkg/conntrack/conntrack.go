// package conntrack implements a connection tracker against the Linux conntrack module to
// watch for connections that are refused or time out when connecting to other systems.
// The tracker tries to keep only (ip,port,proto) tuples that have reported down in
// memory and then reports a rolling window to prometheus of both destination IPs that
// have been down in that window as well as destination ports.
//
// TODO:
// * Because network scanners could generate large numbers of down systems, we have
//   to cap the number of tracked endpoints and IPs.
// * Integrate with a Kube endpoints/node cache to transform IPs into labels for the
//   query (so we could report which pods are down) - endpoints in particular can tell
//   us the node as well. This is best colocated with the kube-proxy or SDN agent.
// * Make sure we can have multiple netlink connections from within a single process
//   if we include it.
// * Consider treating localhost special (exclude?) or maybe that's still useful
//
package conntrack

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// ErrBufferFull is returned if the receive buffer fills up without being
// drained, meaning we lost some events.
var ErrBufferFull = errors.New("receive buffer is full, some events lost")

// Arguments describes the configuration of a connection tracker.
type Arguments struct {
	Interval    time.Duration
	ExpireAfter UIntCounter

	MaxAddresses              int
	MaxDestinationsPerAddress int

	Log bool
}

// WithDefaults sets default values for connection tracking.
func (args Arguments) WithDefaults() Arguments {
	if args.Interval == 0 {
		args.Interval = 15 * time.Second
	}
	if args.ExpireAfter == 0 {
		args.ExpireAfter = 3
	}
	if args.MaxAddresses == 0 {
		args.MaxAddresses = 4096
	}
	if args.MaxDestinationsPerAddress == 0 {
		args.MaxDestinationsPerAddress = 16
	}
	return args
}

// ConnectionTracker records connections that failed to complete, accumulating and expiring
// them after the requested intervals. The tracker limits how many destinations are tracked
// if necessary.
type ConnectionTracker struct {
	args Arguments

	current map[string]DestinationState

	lock sync.RWMutex
	down map[string]DestinationState
}

// New initializes a new connection tracker.
func New(args Arguments) *ConnectionTracker {
	return &ConnectionTracker{
		args:    args.WithDefaults(),
		current: make(map[string]DestinationState),
		down:    make(map[string]DestinationState),
	}
}

func (t *ConnectionTracker) flush() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.args.Log {
		for dst, state := range t.down {
			for target, stats := range state.Connections {
				log.Printf("| %s up=%t port=%d success=%d failure=%d unknown=%d", net.IP(dst), state.Up, target.Port, stats.Success, stats.Failure, stats.Unknown)
			}
		}
		for dst, state := range t.current {
			for target, stats := range state.Connections {
				log.Printf("< %s up=%t port=%d success=%d failure=%d unknown=%d", net.IP(dst), state.Up, target.Port, stats.Success, stats.Failure, stats.Unknown)
			}
		}
	}

	for dst, state := range t.current {
		downState, exists := t.down[dst]

		for target, stats := range state.Connections {
			if stats.Success > 0 {
				delete(state.Connections, target)

				delete(downState.Connections, target)
				if !downState.Up {
					if !exists && len(t.down) > t.args.MaxAddresses {
						continue
					}
					downState.Up = true
					t.down[dst] = downState
				}
				continue
			}
			if stats.Failure > 0 {
				// reset current failure state
				stats.Failure = 0
				state.Connections[target] = stats

				if !exists {
					if !exists && len(t.down) > t.args.MaxAddresses {
						continue
					}
					downState.Up = state.Up
					downState.Connections = make(ConnectionStateMap)
					t.down[dst] = downState
				} else if state.Up != downState.Up {
					downState.Up = state.Up
					t.down[dst] = downState
				}
				if len(downState.Connections) > t.args.MaxDestinationsPerAddress {
					continue
				}
				downState.Connections.Failure(target.Protocol, target.Port)
				continue
			}
			delete(state.Connections, target)
			if state.Up != downState.Up {
				downState.Up = state.Up
				t.down[dst] = downState
			}
		}
		if len(state.Connections) == 0 {
			delete(t.current, dst)
		}
	}

	expired := 0
	for dst, state := range t.down {
		if state.Up && len(state.Connections) == 0 {
			delete(t.down, dst)
			continue
		}
		if len(t.current[dst].Connections) == 0 {
			state := t.down[dst]
			for target, stats := range state.Connections {
				stats.Unknown++
				if stats.Unknown >= t.args.ExpireAfter {
					expired++
					delete(state.Connections, target)
					continue
				}
				state.Connections[target] = stats
			}
			if len(state.Connections) == 0 {
				delete(t.down, dst)
				delete(t.current, dst)
			}
			continue
		}
	}
	if t.args.Log {
		log.Printf("expired=%d down=%d current=%d", expired, len(t.down), len(t.current))
		for dst, state := range t.down {
			for target, stats := range state.Connections {
				log.Printf("| %s up=%t port=%d success=%d failure=%d unknown=%d", net.IP(dst), state.Up, target.Port, stats.Success, stats.Failure, stats.Unknown)
			}
		}
		for dst, state := range t.current {
			for target, stats := range state.Connections {
				log.Printf("< %s up=%t port=%d success=%d failure=%d unknown=%d", net.IP(dst), state.Up, target.Port, stats.Success, stats.Failure, stats.Unknown)
			}
		}
	}
}

func (t *ConnectionTracker) isTrackingIP(ip net.IP) bool {
	state, ok := t.down[string(ip)]
	return ok && !state.Empty()
}

func (t *ConnectionTracker) failure(ip net.IP, protocol uint8, port uint16) (UIntCounter, UIntCounter) {
	t.lock.Lock()
	defer t.lock.Unlock()

	state := t.current[string(ip)]

	var changed bool
	if state.Connections == nil {
		state.Connections = make(ConnectionStateMap)
		changed = true
	}
	if state.Up {
		state.Up = false
		changed = true
	}
	if changed {
		t.current[string(ip)] = state
	}
	if len(state.Connections) > t.args.MaxDestinationsPerAddress {
		return 1, 0
	}
	return state.Connections.Failure(protocol, port)
}

func (t *ConnectionTracker) success(ip net.IP, protocol uint8, port uint16) (UIntCounter, UIntCounter, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	var changed bool
	state := t.current[string(ip)]
	if !state.Up {
		// if we aren't tracking any down targets AND we aren't tracking this IP as down already, we can avoid
		// tracking this IP in general.
		if len(state.Connections) == 0 && !t.isTrackingIP(ip) {
			return 0, 1, false
		}
		state.Up = true
		t.current[string(ip)] = state
		changed = true
	}
	failures, successes, ok := state.Connections.Success(protocol, port)
	return failures, successes, ok || changed
}
