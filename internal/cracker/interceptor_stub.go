//go:build !linux

package cracker

import (
	"context"
	"fmt"
)

// startLinuxInterception is a stub for non-Linux platforms
func (c *Cracker) startLinuxInterception(ctx context.Context, pid int) error {
	return fmt.Errorf("Linux interception not available on this platform")
}

