package sysctl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config represents the sysctl entity input.
type Config struct {
	Sysctl map[string]string `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
	Limits []LimitSpec       `json:"limits,omitempty" yaml:"limits,omitempty"`
}

// LimitSpec defines a resource limit entry for /etc/security/limits.conf.
type LimitSpec struct {
	Domain string `json:"domain" yaml:"domain"`
	Type   string `json:"type" yaml:"type"`   // soft, hard, -
	Item   string `json:"item" yaml:"item"`
	Value  string `json:"value" yaml:"value"`
}

// Result represents the outcome of an apply or validate operation.
type Result struct {
	Success bool           `json:"success"`
	Status  string         `json:"status"`
	Changes []ChangeDetail `json:"changes,omitempty"`
	Errors  []string       `json:"errors,omitempty"`
}

// ChangeDetail describes a single change made or planned.
type ChangeDetail struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Detail   string `json:"detail,omitempty"`
}

var (
	execCommand = exec.Command
	osReadFile  = os.ReadFile
	osWriteFile = os.WriteFile
	osMkdirAll  = os.MkdirAll
)

// validLimitTypes contains the allowed limit type values.
var validLimitTypes = map[string]bool{
	"soft": true,
	"hard": true,
	"-":    true,
}

// Apply sets sysctl parameters and writes limits configuration.
func Apply(cfg *Config) *Result {
	result := &Result{Success: true, Status: "applied"}

	// Apply sysctl parameters
	for key, value := range cfg.Sysctl {
		change, err := applySysctl(key, value)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("sysctl %s: %v", key, err))
			result.Success = false
			continue
		}
		if change != nil {
			result.Changes = append(result.Changes, *change)
		}
	}

	// Persist sysctl parameters to /etc/sysctl.d/99-amadla.conf
	if len(cfg.Sysctl) > 0 {
		if err := persistSysctl(cfg.Sysctl); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("persist sysctl: %v", err))
			result.Success = false
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "written",
				Resource: "file",
				Name:     "/etc/sysctl.d/99-amadla.conf",
				Detail:   fmt.Sprintf("%d parameters persisted", len(cfg.Sysctl)),
			})
		}
	}

	// Apply limits
	if len(cfg.Limits) > 0 {
		// Validate limit types first
		for _, l := range cfg.Limits {
			if !validLimitTypes[l.Type] {
				result.Errors = append(result.Errors, fmt.Sprintf("limit %s: invalid type %q (must be soft, hard, or -)", l.Domain, l.Type))
				result.Success = false
			}
		}

		if result.Success {
			if err := persistLimits(cfg.Limits); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("persist limits: %v", err))
				result.Success = false
			} else {
				result.Changes = append(result.Changes, ChangeDetail{
					Action:   "written",
					Resource: "file",
					Name:     "/etc/security/limits.d/99-amadla.conf",
					Detail:   fmt.Sprintf("%d limit rules written", len(cfg.Limits)),
				})
			}
		}
	}

	if !result.Success {
		result.Status = "failed"
	}

	return result
}

// Validate checks sysctl parameters and limits without making changes.
func Validate(cfg *Config) *Result {
	result := &Result{Success: true, Status: "valid"}

	// Check sysctl parameters
	for key, desired := range cfg.Sysctl {
		current, err := readSysctl(key)
		if err != nil {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "set",
				Resource: "sysctl",
				Name:     key,
				Detail:   fmt.Sprintf("will set to %s (current unknown)", desired),
			})
			continue
		}

		if current != desired {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "update",
				Resource: "sysctl",
				Name:     key,
				Detail:   fmt.Sprintf("current=%s desired=%s", current, desired),
			})
		} else {
			result.Changes = append(result.Changes, ChangeDetail{
				Action:   "ok",
				Resource: "sysctl",
				Name:     key,
				Detail:   "no changes needed",
			})
		}
	}

	// Validate limits
	for _, l := range cfg.Limits {
		if !validLimitTypes[l.Type] {
			result.Errors = append(result.Errors, fmt.Sprintf("limit %s: invalid type %q (must be soft, hard, or -)", l.Domain, l.Type))
			result.Success = false
			continue
		}
		result.Changes = append(result.Changes, ChangeDetail{
			Action:   "set",
			Resource: "limit",
			Name:     fmt.Sprintf("%s %s %s", l.Domain, l.Type, l.Item),
			Detail:   l.Value,
		})
	}

	if !result.Success {
		result.Status = "invalid"
	}

	return result
}

func applySysctl(key, value string) (*ChangeDetail, error) {
	param := fmt.Sprintf("%s=%s", key, value)
	cmd := execCommand("sysctl", "-w", param)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sysctl -w failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return &ChangeDetail{
		Action:   "set",
		Resource: "sysctl",
		Name:     key,
		Detail:   value,
	}, nil
}

func readSysctl(key string) (string, error) {
	cmd := execCommand("sysctl", "-n", key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sysctl read failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func persistSysctl(params map[string]string) error {
	var lines []string
	lines = append(lines, "# Managed by amadla enjoin-sysctl - do not edit manually")
	for key, value := range params {
		lines = append(lines, fmt.Sprintf("%s = %s", key, value))
	}
	content := strings.Join(lines, "\n") + "\n"

	dir := filepath.Dir("/etc/sysctl.d/99-amadla.conf")
	if err := osMkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	return osWriteFile("/etc/sysctl.d/99-amadla.conf", []byte(content), 0644)
}

func persistLimits(limits []LimitSpec) error {
	var lines []string
	lines = append(lines, "# Managed by amadla enjoin-sysctl - do not edit manually")
	for _, l := range limits {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s", l.Domain, l.Type, l.Item, l.Value))
	}
	content := strings.Join(lines, "\n") + "\n"

	dir := filepath.Dir("/etc/security/limits.d/99-amadla.conf")
	if err := osMkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	return osWriteFile("/etc/security/limits.d/99-amadla.conf", []byte(content), 0644)
}
