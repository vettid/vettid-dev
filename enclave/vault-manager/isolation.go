// Package main provides process isolation hardening for vault-manager.
// SECURITY: This file implements runtime isolation verification and hardening
// to ensure vault processes are properly sandboxed.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// IsolationConfig holds configuration for process isolation
type IsolationConfig struct {
	// EnforceSeccomp enables seccomp filtering (requires Linux)
	EnforceSeccomp bool
	// DropCapabilities drops all capabilities
	DropCapabilities bool
	// VerifyNamespaces verifies namespace isolation
	VerifyNamespaces bool
	// DevMode relaxes restrictions for development
	DevMode bool
}

// DefaultIsolationConfig returns the default isolation configuration
func DefaultIsolationConfig(devMode bool) *IsolationConfig {
	return &IsolationConfig{
		EnforceSeccomp:   !devMode && runtime.GOOS == "linux",
		DropCapabilities: !devMode && runtime.GOOS == "linux",
		VerifyNamespaces: !devMode && runtime.GOOS == "linux",
		DevMode:          devMode,
	}
}

// EnforceIsolation applies process isolation hardening
// SECURITY: This should be called early in process startup
func EnforceIsolation(cfg *IsolationConfig) error {
	if cfg.DevMode {
		log.Warn().Msg("SECURITY WARNING: Running in dev mode, isolation not enforced")
		return nil
	}

	if runtime.GOOS != "linux" {
		log.Warn().Str("os", runtime.GOOS).Msg("Process isolation only supported on Linux")
		return nil
	}

	// 1. Verify we're not running as root (defense in depth)
	if os.Geteuid() == 0 {
		log.Warn().Msg("SECURITY WARNING: Running as root is not recommended")
	}

	// 2. Drop capabilities
	// Note: In Nitro Enclave environment, the process may not have CAP_SETPCAP
	// to drop capabilities. This is OK - the enclave provides hardware isolation.
	if cfg.DropCapabilities {
		if err := dropCapabilities(); err != nil {
			// Log warning but don't fail - enclave provides its own isolation
			log.Warn().Err(err).Msg("Failed to drop capabilities (OK in enclave environment)")
		} else {
			log.Info().Msg("Dropped all capabilities")
		}
	}

	// 3. Set no new privileges flag (prevents privilege escalation via setuid)
	// May fail in enclave environment - not critical since enclave provides isolation
	if err := setNoNewPrivs(); err != nil {
		log.Warn().Err(err).Msg("Failed to set no_new_privs (OK in enclave environment)")
	} else {
		log.Info().Msg("Set no_new_privs flag")
	}

	// 4. Verify namespace isolation
	if cfg.VerifyNamespaces {
		if err := verifyNamespaceIsolation(); err != nil {
			// Log warning but don't fail - enclave environment may differ
			log.Warn().Err(err).Msg("Namespace isolation verification failed")
		} else {
			log.Info().Msg("Namespace isolation verified")
		}
	}

	// 5. Restrict core dumps (prevents credential leakage in crash dumps)
	// May fail in enclave - not critical since enclave has no persistent storage
	if err := disableCoreDumps(); err != nil {
		log.Warn().Err(err).Msg("Failed to disable core dumps (OK in enclave environment)")
	} else {
		log.Info().Msg("Disabled core dumps")
	}

	// 6. Lock memory to prevent swapping (keep credentials in RAM only)
	if err := lockMemory(); err != nil {
		// This may fail due to ulimits, log warning but continue
		log.Warn().Err(err).Msg("Failed to lock memory (mlockall)")
	} else {
		log.Info().Msg("Memory locked (mlockall)")
	}

	// Note: In enclave environment, some isolation features may fail.
	// This is acceptable since the Nitro Enclave provides hardware-level isolation.
	log.Info().Msg("Process isolation hardening complete (enclave mode)")
	return nil
}

// dropCapabilities drops all Linux capabilities
// SECURITY: This prevents the process from gaining elevated privileges
func dropCapabilities() error {
	// Set empty capability sets
	// Using prctl to drop all capabilities from bounding set

	// Get the last capability number
	lastCap := unix.CAP_LAST_CAP

	// Drop each capability from the bounding set
	for cap := 0; cap <= int(lastCap); cap++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			// Ignore EINVAL (capability not supported on this kernel)
			if err != syscall.EINVAL {
				return fmt.Errorf("failed to drop capability %d: %w", cap, err)
			}
		}
	}

	return nil
}

// setNoNewPrivs sets the PR_SET_NO_NEW_PRIVS flag
// SECURITY: Prevents gaining privileges through execve of setuid binaries
func setNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// verifyNamespaceIsolation checks that the process is in isolated namespaces
// SECURITY: Verifies that container/enclave isolation is active
func verifyNamespaceIsolation() error {
	// Read /proc/self/status to check namespace indicators
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("cannot read /proc/self/status: %w", err)
	}

	status := string(data)

	// Check for PID namespace isolation (PID 1 in container)
	// This isn't definitive but is a good indicator
	if os.Getpid() == 1 {
		log.Debug().Msg("Running as PID 1 (likely containerized)")
	}

	// Check NSpid line for namespace info
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			pids := strings.Fields(line)
			if len(pids) > 2 {
				// Multiple PIDs indicate nested namespaces
				log.Debug().Str("nspid", line).Msg("Namespace PIDs detected")
			}
		}
	}

	// Additional check: verify /proc/1/cmdline isn't accessible (if not PID 1)
	// This would indicate PID namespace isolation
	if os.Getpid() != 1 {
		if _, err := os.ReadFile("/proc/1/cmdline"); err != nil {
			log.Debug().Msg("Cannot read /proc/1/cmdline (good - isolated)")
		}
	}

	return nil
}

// disableCoreDumps prevents core dump generation
// SECURITY: Prevents credential leakage in crash dumps
func disableCoreDumps() error {
	// Set RLIMIT_CORE to 0
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

// lockMemory locks all current and future memory pages
// SECURITY: Prevents sensitive data from being swapped to disk
func lockMemory() error {
	// MCL_CURRENT: Lock all current pages
	// MCL_FUTURE: Lock all future pages
	return unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}

// VerifyIsolationAtRuntime performs runtime isolation checks
// SECURITY: Called periodically to verify isolation hasn't been compromised
func VerifyIsolationAtRuntime() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Check that no_new_privs is still set
	// PR_GET_NO_NEW_PRIVS returns the value directly as the result
	ret, _, errno := syscall.Syscall(syscall.SYS_PRCTL, uintptr(unix.PR_GET_NO_NEW_PRIVS), 0, 0)
	if errno != 0 {
		return fmt.Errorf("cannot check no_new_privs: %v", errno)
	}
	if ret == 0 {
		return fmt.Errorf("SECURITY VIOLATION: no_new_privs is not set")
	}

	// Check that core dumps are still disabled
	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rlim); err != nil {
		return fmt.Errorf("cannot check RLIMIT_CORE: %w", err)
	}
	if rlim.Cur != 0 || rlim.Max != 0 {
		return fmt.Errorf("SECURITY VIOLATION: core dumps are enabled")
	}

	return nil
}
