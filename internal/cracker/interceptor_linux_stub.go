//go:build linux

package cracker

import (
	"context"
	"fmt"
)

// startWindowsInterception is a stub on Linux
func (c *Cracker) startWindowsInterception(ctx context.Context, pid int) error {
	return fmt.Errorf("Windows interception not available on Linux")
}

