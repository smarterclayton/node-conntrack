package conntrack

import (
	"net"
	_ "net/http/pprof"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	gaugeEvents = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "down_target_connection_event_count",
		Help: "The count of connection events received by the connection tracker",
	}, nil)
	gaugeFilteredEvents = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "down_target_filtered_connection_event_count",
		Help: "The count of connection events filtered out by the connection tracker",
	}, nil)
	gaugeBufferFullErrors = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "down_target_buffer_full_errors",
		Help: "The number of times the receive buffer has filled up and we have dropped some events.",
	}, nil)
	descTargets = prometheus.NewDesc(
		"down_target",
		"Reports the value one if the remote target with the provided address could not be reached during a connection attempt in the last minute.",
		[]string{"ip"},
		nil,
	)
	descTargetPorts = prometheus.NewDesc(
		"down_target_ports",
		"Reports the value one if the remote ip, port, and protocol could not be reached during a connection attempt in the last minute.",
		[]string{"ip", "proto", "port"},
		nil,
	)
)

func (t *ConnectionTracker) Describe(ch chan<- *prometheus.Desc) {
	gaugeEvents.Describe(ch)
	gaugeFilteredEvents.Describe(ch)
	gaugeBufferFullErrors.Describe(ch)
	ch <- descTargets
	ch <- descTargetPorts
}

var protocols = map[uint8]string{
	unix.IPPROTO_ICMP:   "icmp",
	unix.IPPROTO_IGMP:   "igmp",
	unix.IPPROTO_TCP:    "tcp",
	unix.IPPROTO_UDP:    "udp",
	unix.IPPROTO_ICMPV6: "ipv6-icmp",
}

func (t *ConnectionTracker) Collect(ch chan<- prometheus.Metric) {
	gaugeEvents.Collect(ch)
	gaugeFilteredEvents.Collect(ch)
	gaugeBufferFullErrors.Collect(ch)

	t.lock.RLock()
	defer t.lock.RUnlock()

	for dst, state := range t.down {
		if !state.Up {
			ch <- prometheus.MustNewConstMetric(descTargets, prometheus.GaugeValue, 1, net.IP([]byte(dst)).String())
		}
		for target, stats := range state.Connections {
			var failures float64
			if stats.Failure > 0 {
				failures = 1
			}

			ch <- prometheus.MustNewConstMetric(descTargetPorts, prometheus.GaugeValue, failures, net.IP([]byte(dst)).String(), protocols[target.Protocol], strconv.Itoa(int(target.Port)))
		}
	}
}
