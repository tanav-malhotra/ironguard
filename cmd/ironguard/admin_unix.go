//go:build !windows

package main

// isAdminWindows is a stub for non-Windows platforms.
// On Unix, we use os.Geteuid() == 0 in the main isAdmin function.
func isAdminWindows() bool {
	return false
}

