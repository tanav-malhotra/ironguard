package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tanav-malhotra/ironguard/internal/harden"
)

// RegisterHardenTools adds CyberPatriot hardening tools to the registry.
func (r *Registry) RegisterHardenTools() {
	h := harden.New()

	// List users
	r.Register(&Tool{
		Name:        "list_users",
		Description: "List all local user accounts on the system",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			users, err := h.ListUsers(ctx)
			if err != nil {
				return "", err
			}
			return strings.Join(users, "\n"), nil
		},
		Mutating: false,
	})

	// List admins
	r.Register(&Tool{
		Name:        "list_admins",
		Description: "List users with administrative/sudo privileges",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			admins, err := h.ListAdmins(ctx)
			if err != nil {
				return "", err
			}
			return strings.Join(admins, "\n"), nil
		},
		Mutating: false,
	})

	// Disable user
	r.Register(&Tool{
		Name:        "disable_user",
		Description: "Disable a user account (lock the account)",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username": map[string]interface{}{
					"type":        "string",
					"description": "The username to disable",
				},
			},
			"required": []string{"username"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Username string `json:"username"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.DisableUser(ctx, params.Username)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Delete user
	r.Register(&Tool{
		Name:        "delete_user",
		Description: "Delete a user account from the system",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username": map[string]interface{}{
					"type":        "string",
					"description": "The username to delete",
				},
			},
			"required": []string{"username"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Username string `json:"username"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.DeleteUser(ctx, params.Username)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Set password
	r.Register(&Tool{
		Name:        "set_password",
		Description: "Set a user's password to a secure value",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username": map[string]interface{}{
					"type":        "string",
					"description": "The username",
				},
				"password": map[string]interface{}{
					"type":        "string",
					"description": "The new password (should be strong)",
				},
			},
			"required": []string{"username", "password"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.SetPassword(ctx, params.Username, params.Password)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Remove from admins
	r.Register(&Tool{
		Name:        "remove_from_admins",
		Description: "Remove a user from the administrators/sudo group",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"username": map[string]interface{}{
					"type":        "string",
					"description": "The username to demote",
				},
			},
			"required": []string{"username"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Username string `json:"username"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.RemoveFromAdmins(ctx, params.Username)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// List services
	r.Register(&Tool{
		Name:        "list_services",
		Description: "List all services on the system",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			services, err := h.ListServices(ctx)
			if err != nil {
				return "", err
			}
			return strings.Join(services, "\n"), nil
		},
		Mutating: false,
	})

	// List running services
	r.Register(&Tool{
		Name:        "list_running_services",
		Description: "List currently running services",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			services, err := h.ListRunningServices(ctx)
			if err != nil {
				return "", err
			}
			return strings.Join(services, "\n"), nil
		},
		Mutating: false,
	})

	// Stop service
	r.Register(&Tool{
		Name:        "stop_service",
		Description: "Stop a running service",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service": map[string]interface{}{
					"type":        "string",
					"description": "The service name to stop",
				},
			},
			"required": []string{"service"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Service string `json:"service"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.StopService(ctx, params.Service)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Disable service
	r.Register(&Tool{
		Name:        "disable_service",
		Description: "Disable a service from starting at boot",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service": map[string]interface{}{
					"type":        "string",
					"description": "The service name to disable",
				},
			},
			"required": []string{"service"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Service string `json:"service"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.DisableService(ctx, params.Service)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Enable firewall
	r.Register(&Tool{
		Name:        "enable_firewall",
		Description: "Enable the system firewall (Windows Firewall or ufw/firewalld)",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			result := h.EnableFirewall(ctx)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Check updates
	r.Register(&Tool{
		Name:        "check_updates",
		Description: "Check for available system updates",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			return h.CheckUpdates(ctx)
		},
		Mutating: false,
	})

	// Install updates
	r.Register(&Tool{
		Name:        "install_updates",
		Description: "Install all available system updates",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			result := h.InstallUpdates(ctx)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Set password policy
	r.Register(&Tool{
		Name:        "set_password_policy",
		Description: "Configure password complexity requirements (min length, complexity, history)",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			result := h.SetPasswordPolicy(ctx)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Disable guest account
	r.Register(&Tool{
		Name:        "disable_guest",
		Description: "Disable the guest account",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			result := h.DisableGuestAccount(ctx)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Find prohibited files
	r.Register(&Tool{
		Name:        "find_prohibited_files",
		Description: "Search for prohibited media files (mp3, mp4, avi, etc.) in user directories",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			return h.FindProhibitedFiles(ctx)
		},
		Mutating: false,
	})

	// Delete file
	r.Register(&Tool{
		Name:        "delete_file",
		Description: "Delete a file from the system",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The file path to delete",
				},
			},
			"required": []string{"path"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var params struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			result := h.DeleteFile(ctx, params.Path)
			if !result.Success {
				return "", fmt.Errorf(result.Error)
			}
			return result.Output, nil
		},
		Mutating: true,
	})

	// Security audit
	r.Register(&Tool{
		Name:        "security_audit",
		Description: "Perform a comprehensive security audit of the system",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			return h.AuditSystem(ctx)
		},
		Mutating: false,
	})
}

