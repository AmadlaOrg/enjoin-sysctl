package sysctl

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate_SysctlParams(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		// Mock "sysctl -n key" to return current value
		if len(arg) >= 2 && arg[0] == "-n" {
			switch arg[1] {
			case "net.ipv4.ip_forward":
				return exec.Command("echo", "0")
			case "vm.swappiness":
				return exec.Command("echo", "60")
			}
		}
		return exec.Command("echo", "")
	}

	cfg := &Config{
		Sysctl: map[string]string{
			"net.ipv4.ip_forward": "1",
			"vm.swappiness":      "60",
		},
	}

	result := Validate(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "valid", result.Status)
	assert.Len(t, result.Changes, 2)

	// Find the changes by name
	changeMap := make(map[string]ChangeDetail)
	for _, c := range result.Changes {
		changeMap[c.Name] = c
	}

	ipForward := changeMap["net.ipv4.ip_forward"]
	assert.Equal(t, "update", ipForward.Action)
	assert.Contains(t, ipForward.Detail, "current=0")

	swappiness := changeMap["vm.swappiness"]
	assert.Equal(t, "ok", swappiness.Action)
}

func TestValidate_ValidLimits(t *testing.T) {
	cfg := &Config{
		Limits: []LimitSpec{
			{Domain: "*", Type: "soft", Item: "nofile", Value: "65536"},
			{Domain: "root", Type: "hard", Item: "nproc", Value: "unlimited"},
			{Domain: "@developers", Type: "-", Item: "memlock", Value: "unlimited"},
		},
	}

	result := Validate(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "valid", result.Status)
	assert.Len(t, result.Changes, 3)
	for _, c := range result.Changes {
		assert.Equal(t, "set", c.Action)
		assert.Equal(t, "limit", c.Resource)
	}
}

func TestValidate_InvalidLimitType(t *testing.T) {
	cfg := &Config{
		Limits: []LimitSpec{
			{Domain: "*", Type: "invalid", Item: "nofile", Value: "65536"},
		},
	}

	result := Validate(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "invalid", result.Status)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "invalid type")
}

func TestApply_SysctlParams(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "ok")
	}

	origWrite := osWriteFile
	defer func() { osWriteFile = origWrite }()
	osWriteFile = func(name string, data []byte, perm os.FileMode) error {
		return nil
	}

	origMkdir := osMkdirAll
	defer func() { osMkdirAll = origMkdir }()
	osMkdirAll = func(path string, perm os.FileMode) error {
		return nil
	}

	cfg := &Config{
		Sysctl: map[string]string{
			"net.ipv4.ip_forward": "1",
			"vm.swappiness":      "10",
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	// 2 sysctl set + 1 file persist
	assert.Len(t, result.Changes, 3)
}

func TestApply_Limits(t *testing.T) {
	origWrite := osWriteFile
	defer func() { osWriteFile = origWrite }()
	var writtenContent string
	osWriteFile = func(name string, data []byte, perm os.FileMode) error {
		writtenContent = string(data)
		return nil
	}

	origMkdir := osMkdirAll
	defer func() { osMkdirAll = origMkdir }()
	osMkdirAll = func(path string, perm os.FileMode) error {
		return nil
	}

	cfg := &Config{
		Limits: []LimitSpec{
			{Domain: "*", Type: "soft", Item: "nofile", Value: "65536"},
			{Domain: "root", Type: "hard", Item: "nproc", Value: "unlimited"},
		},
	}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "written", result.Changes[0].Action)
	assert.Equal(t, "/etc/security/limits.d/99-amadla.conf", result.Changes[0].Name)
	assert.Contains(t, writtenContent, "*\tsoft\tnofile\t65536")
	assert.Contains(t, writtenContent, "root\thard\tnproc\tunlimited")
}

func TestApply_EmptyConfig(t *testing.T) {
	cfg := &Config{}

	result := Apply(cfg)
	assert.True(t, result.Success)
	assert.Equal(t, "applied", result.Status)
	assert.Empty(t, result.Changes)
}

func TestApply_InvalidLimitType(t *testing.T) {
	cfg := &Config{
		Limits: []LimitSpec{
			{Domain: "*", Type: "bogus", Item: "nofile", Value: "65536"},
		},
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "invalid type")
}

func TestApply_SysctlCommandFails(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("false")
	}

	origWrite := osWriteFile
	defer func() { osWriteFile = origWrite }()
	osWriteFile = func(name string, data []byte, perm os.FileMode) error {
		return nil
	}

	origMkdir := osMkdirAll
	defer func() { osMkdirAll = origMkdir }()
	osMkdirAll = func(path string, perm os.FileMode) error {
		return nil
	}

	cfg := &Config{
		Sysctl: map[string]string{
			"net.ipv4.ip_forward": "1",
		},
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
	assert.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "sysctl -w failed")
}

func TestApply_PersistSysctlFails(t *testing.T) {
	origCmd := execCommand
	defer func() { execCommand = origCmd }()
	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("echo", "ok")
	}

	origWrite := osWriteFile
	defer func() { osWriteFile = origWrite }()
	osWriteFile = func(name string, data []byte, perm os.FileMode) error {
		return fmt.Errorf("permission denied")
	}

	origMkdir := osMkdirAll
	defer func() { osMkdirAll = origMkdir }()
	osMkdirAll = func(path string, perm os.FileMode) error {
		return nil
	}

	cfg := &Config{
		Sysctl: map[string]string{
			"vm.swappiness": "10",
		},
	}

	result := Apply(cfg)
	assert.False(t, result.Success)
	assert.Equal(t, "failed", result.Status)
	assert.Contains(t, result.Errors[0], "persist sysctl")
}
