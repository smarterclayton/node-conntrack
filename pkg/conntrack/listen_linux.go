// +build linux

package conntrack

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

type Event struct {
	Type      conntrack.EventType
	TupleOrig conntrack.Tuple
	Status    conntrack.Status
}

// Listen connects to the netlink socket and begins listening for Update and Destroy connection events. Failed
// connections (due to rejections or timeouts) are recorded, while successful connections reset the record.
// After each interval the current set of records are merged and visible when metrics are collected. The method
// exits when the context is closed or all event workers encounter an error.
func (t *ConnectionTracker) Listen(ctx context.Context) error {
	conn, err := conntrack.Dial(&netlink.Config{DisableNSLockThread: true})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetReadBufferForce(1 * 1024 * 1024); err != nil {
		return err
	}

	workers := uint8(1)
	eventCh := make(chan Event, 1024*int(workers))
	// TODO: out of order events
	dropCounter := gaugeDroppedEvents.WithLabelValues()
	filterCounter := gaugeFilteredEvents.WithLabelValues()
	errCh, err := conn.ListenRaw(workers, []netfilter.NetlinkGroup{netfilter.GroupCTDestroy, netfilter.GroupCTUpdate}, func(recv []netlink.Message) error {
		var flow conntrack.Flow
		var event Event

		ok, err := netfilter.WalkMessage(
			recv[0],
			func(h netfilter.Header) (bool, error) {
				if h.SubsystemID != netfilter.NFSubsysCTNetlink {
					return false, nil
				}
				if err := event.Type.Unmarshal(h); err != nil {
					return false, err
				}
				switch event.Type {
				case conntrack.EventDestroy, conntrack.EventUpdate:
					return true, nil
				default:
					return false, nil
				}
			},
			func(attr netfilter.Attribute) (bool, error) {
				switch conntrack.AttributeType(attr.Type) {
				case conntrack.CTAStatus:
					if event.Type != conntrack.EventDestroy {
						return true, nil
					}
					if err := flow.Unmarshal([]netfilter.Attribute{attr}); err != nil {
						return false, err
					}
					if flow.Status.SeenReply() {
						return false, nil
					}
				case conntrack.CTATupleOrig:
					if err := attr.UnmarshalNested(); err != nil {
						return false, err
					}
					if err := flow.Unmarshal([]netfilter.Attribute{attr}); err != nil {
						return false, err
					}
					if flow.TupleOrig.Proto.Protocol != unix.IPPROTO_TCP {
						return false, nil
					}
				}
				return true, nil
			},
		)
		if err != nil {
			return err
		}
		if !ok {
			filterCounter.Inc()
			return nil
		}

		event.TupleOrig = flow.TupleOrig
		event.Status = flow.Status

		select {
		case eventCh <- event:
		default:
			dropCounter.Inc()
		}
		return nil
	})
	if err != nil {
		return err
	}

	// flush stats from current to down without blocking the main event loop
	ticker := time.NewTicker(t.args.Interval)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			t.flush()
		}
	}()

	counter := gaugeEvents.WithLabelValues()
	var errs []error
	for workers > 0 {
		select {
		case err, ok := <-errCh:
			if !ok {
				return nil
			}
			if err != nil {
				errs = append(errs, err)
			}
			workers--

		case <-ctx.Done():
			workers = 0
			errs = append(errs, context.Canceled)

		case event, ok := <-eventCh:
			// we will try to read up to 256 events (if the channel has a backlog) before exiting the core loop
		Continue:
			if !ok {
				workers = 0
				continue
			}

			// drop everything except TCP for now
			switch event.TupleOrig.Proto.Protocol {
			case unix.IPPROTO_TCP:
			default:
				continue
			}
			counter.Inc()
			switch event.Type {
			case conntrack.EventDestroy:
				if !event.Status.SeenReply() {
					dst := event.TupleOrig
					failures, successes := t.failure(dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort)
					if t.args.Log {
						log.Printf("down ip=%s proto=%d port=%d down=%d up=%d", dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort, failures, successes)
					}
				}
			case conntrack.EventUpdate:
				dst := event.TupleOrig
				failures, successes, ok := t.success(dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort)
				if ok {
					if t.args.Log {
						log.Printf("up ip=%s proto=%d port=%d down=%d up=%d", dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort, failures, successes)
					}
				}

			default:
				log.Printf("unrecognized event: %s", event.Type)
			}

			// loop if we can read more events, otherwise go back to the main select
			if len(eventCh) > 0 {
				event, ok = <-eventCh
				goto Continue
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	var msgs []string
	for _, err := range errs {
		msgs = append(msgs, err.Error())
	}
	return fmt.Errorf("unable to listen to events: %s", strings.Join(msgs, ", "))
}
