// package main implements a connection tracker against the Linux conntrack module to
// watch for connections that are refused or time out when connecting to other systems.
// The tracker tries to keep only (ip,port,proto) tuples that have reported down in
// memory and then reports a rolling window to prometheus of both destination IPs that
// have been down in that window as well as destination ports.
//
// TODO:
// * Because network scanners could generate large numbers of down systems, we have
//   to cap the number of tracked endpoints and IPs (and probably report the number
//   dropped).
// * Summarize stats on total failed connections.
// * Integrate with a Kube endpoints/node cache to transform IPs into labels for the
//   query (so we could report which pods are down) - endpoints in particular can tell
//   us the node as well. This is best colocated with the kube-proxy or SDN agent.
// * Verify assomptions about connection tracking and check memory consumption on
//   fast systems - i.e. will we also catch connections that time out abnormally?
// * Make this an easily includeable package for vendoring
// * Make sure we can have multiple netlink connections from within a single process
//   if we include it.
// * Consider treating localhost special (exclude?) or maybe that's still useful
//
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/smarterclayton/node-conntrack/pkg/conntrack"
)

type options struct {
	Listen  string
	Verbose bool
}

func main() {
	o := options{
		Listen: ":9179",
	}
	flag.CommandLine.StringVar(&o.Listen, "listen", o.Listen, "Address and port to listen on for metrics")
	flag.CommandLine.BoolVar(&o.Verbose, "v", o.Verbose, "Write verbose output")
	flag.Parse()

	tracker := conntrack.New(conntrack.Arguments{Log: o.Verbose})

	go func() {
		metrics := prometheus.NewRegistry()
		metrics.MustRegister(tracker)
		http.Handle("/metrics", promhttp.HandlerFor(metrics, promhttp.HandlerOpts{}))
		if err := http.ListenAndServe(o.Listen, nil); err != nil {
			log.Fatal(err)
		}
	}()

	ctx := context.Background()
	if err := tracker.Listen(ctx); err != nil {
		log.Fatal(err)
	}
}
