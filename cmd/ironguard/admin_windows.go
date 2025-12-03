//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// isAdminWindows checks if the current process has administrator privileges on Windows.
func isAdminWindows() bool {
	var sid *windows.SID
	
	// Create a SID for the Administrators group
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	
	// Check if the current process token contains this SID
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	
	return member
}

