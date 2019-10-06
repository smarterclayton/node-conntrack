// +build !linux

package conntrack

import (
	"context"
	"fmt"
)

// Listen is only supported on Linux platforms.
func (t *ConnectionTracker) Listen(ctx context.Context) error {
	return fmt.Errorf("conntrack is not supported on non-Linux platforms")
}
