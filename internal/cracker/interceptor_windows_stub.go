//go:build windows

package cracker

import (
	"context"
	"fmt"
)

// startLinuxInterception is a stub on Windows
func (c *Cracker) startLinuxInterception(ctx context.Context, pid int) error {
	return fmt.Errorf("Linux interception not available on Windows")
}

