package conntrack

import (
	"fmt"
	"testing"
)

// Create references to unused enums (deprecated or other) to avoid tripping go-unused.
// These consts cannot be removed as they would break the iota sequence.
func TestUnusedEnums(t *testing.T) {
	_ = fmt.Sprint(
		ctGetCtrZero,     // TODO(timo): Could be added as feature
		ctGetDying,       // Narrow time window for query
		ctGetUnconfirmed, // Narrow time window for query
		ctExpGet,         // Haven't figured out how to create expects, so there's nothing to Get()
		ctaNatSrc,        // Deprecated
		ctaNatDst,        // Deprecated
		ctaSecMark,       // Deprecated

		// All the below is unused
		ctaTupleUnspec,
		ctaProtoUnspec,
		ctaIPUnspec,
		ctaTimestampPad,
		ctaProtoInfoDCCPPad,
		ctaExpectUnspec,
		ctaExpectNATUnspec,
		ctaStatsUnspec,
		ctaStatsGlobalUnspec,
		ctaStatsExpUnspec,
	)
}
