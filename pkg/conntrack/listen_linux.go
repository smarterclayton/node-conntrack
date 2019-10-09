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

	counter := gaugeEvents.WithLabelValues()
	filterCounter := gaugeFilteredEvents.WithLabelValues()

	workers := uint8(1)
	errCh, err := conn.ListenRaw(workers, []netfilter.NetlinkGroup{netfilter.GroupCTDestroy, netfilter.GroupCTUpdate}, func(recv []netlink.Message) error {
		var flow conntrack.Flow
		var eventType conntrack.EventType

		ok, err := netfilter.WalkMessage(
			recv[0],
			func(h netfilter.Header) (bool, error) {
				if h.SubsystemID != netfilter.NFSubsysCTNetlink {
					return false, nil
				}
				if err := eventType.Unmarshal(h); err != nil {
					return false, err
				}
				switch eventType {
				case conntrack.EventDestroy, conntrack.EventUpdate:
					return true, nil
				default:
					return false, nil
				}
			},
			func(attr netfilter.Attribute) (bool, error) {
				switch conntrack.AttributeType(attr.Type) {
				case conntrack.CTAStatus:
					if eventType != conntrack.EventDestroy {
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

		switch eventType {
		case conntrack.EventDestroy:
			if flow.Status.SeenReply() {
				filterCounter.Inc()
				return nil
			}
			dst := flow.TupleOrig
			failures, successes := t.failure(dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort)
			counter.Inc()
			if t.args.Log {
				log.Printf("down ip=%s proto=%d port=%d down=%d up=%d", dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort, failures, successes)
			}

		case conntrack.EventUpdate:
			dst := flow.TupleOrig
			failures, successes, ok := t.success(dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort)
			if !ok {
				filterCounter.Inc()
				return nil
			}
			counter.Inc()
			if t.args.Log {
				log.Printf("up ip=%s proto=%d port=%d down=%d up=%d tracked=%t", dst.IP.DestinationAddress, dst.Proto.Protocol, dst.Proto.DestinationPort, failures, successes, ok)
			}

		default:
			filterCounter.Inc()
			return nil
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

	var errs []error
	var errBufferFull bool
	for workers > 0 {
		select {
		case err, ok := <-errCh:
			if !ok {
				return nil
			}
			if err != nil {
				switch {
				case strings.Contains(err.Error(), "recvmsg: no buffer space available"):
					errBufferFull = true
				default:
					errs = append(errs, err)
				}
			}
			workers--

		case <-ctx.Done():
			workers = 0
			errs = append(errs, context.Canceled)
		}
	}

	if len(errs) == 0 {
		if errBufferFull {
			gaugeBufferFullErrors.WithLabelValues().Inc()
			return ErrBufferFull
		}
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
