package hooks

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Phase represents a scan lifecycle phase for hook execution.
type Phase string

const (
	PhasePreScan       Phase = "pre-scan"       // Before any network activity
	PhasePostDiscovery Phase = "post-discovery"  // After crawl, before heuristic
	PhasePostConfirm   Phase = "post-confirm"    // After Phase 2, before exploitation
	PhasePostExploit   Phase = "post-exploit"    // After Phase 3, before reporting
	PhasePostReport    Phase = "post-report"     // After reports are written
)

// HookContext carries scan state data available to hooks.
type HookContext struct {
	Phase        Phase             `json:"phase"`
	TargetURL    string            `json:"target_url"`
	Operator     string            `json:"operator"`
	EngagementID string            `json:"engagement_id"`
	Timestamp    string            `json:"timestamp"`
	Data         map[string]interface{} `json:"data,omitempty"`
}

// Hook represents a single registered hook action.
type Hook struct {
	Name    string `toml:"name"`
	Phase   Phase  `toml:"phase"`
	Command string `toml:"command"` // shell command to execute
	Args    string `toml:"args"`    // additional args (supports {{.TargetURL}} templates)
	Timeout int    `toml:"timeout"` // seconds, default 30
}

// Registry holds all registered hooks.
type Registry struct {
	hooks []Hook
}

var globalRegistry = &Registry{}

// Register adds a hook to the global registry.
func Register(h Hook) {
	globalRegistry.hooks = append(globalRegistry.hooks, h)
}

// RegisterAll bulk-registers hooks (from config file).
func RegisterAll(hooks []Hook) {
	globalRegistry.hooks = append(globalRegistry.hooks, hooks...)
}

// Run executes all hooks registered for the given phase.
// Hook context is passed as JSON via stdin to the subprocess.
func Run(phase Phase, ctx HookContext) {
	ctx.Phase = phase
	ctx.Timestamp = time.Now().UTC().Format(time.RFC3339)

	for _, h := range globalRegistry.hooks {
		if h.Phase != phase {
			continue
		}
		log.Printf("[HOOK] Running %q (%s)…", h.Name, phase)
		if err := executeHook(h, ctx); err != nil {
			log.Printf("[HOOK] ⚠ %q failed: %v", h.Name, err)
		} else {
			log.Printf("[HOOK] ✓ %q completed", h.Name)
		}
	}
}

// Count returns the number of hooks registered for a phase.
func Count(phase Phase) int {
	count := 0
	for _, h := range globalRegistry.hooks {
		if h.Phase == phase {
			count++
		}
	}
	return count
}

func executeHook(h Hook, ctx HookContext) error {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	// Template substitution in args
	args := h.Args
	args = strings.ReplaceAll(args, "{{.TargetURL}}", ctx.TargetURL)
	args = strings.ReplaceAll(args, "{{.Operator}}", ctx.Operator)
	args = strings.ReplaceAll(args, "{{.EngagementID}}", ctx.EngagementID)
	args = strings.ReplaceAll(args, "{{.Phase}}", string(ctx.Phase))

	// Build command
	cmdParts := strings.Fields(h.Command)
	if args != "" {
		cmdParts = append(cmdParts, strings.Fields(args)...)
	}
	if len(cmdParts) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Pass context as JSON on stdin
	ctxJSON, _ := json.Marshal(ctx)
	cmd.Stdin = strings.NewReader(string(ctxJSON))

	// Run with timeout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start hook %q: %w", h.Command, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-time.After(time.Duration(timeout) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return fmt.Errorf("timeout after %ds", timeout)
	}
}

// LoadHooksFromDir scans a directory for executable hook scripts and auto-registers
// them based on filename convention: <phase>_<name>.<ext>
// e.g., "pre-scan_notify-slack.sh", "post-report_upload-s3.py"
func LoadHooksFromDir(dir string) error {
	if dir == "" {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot read hooks dir %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Parse phase from filename prefix
		phase, hookName := parseHookFilename(name)
		if phase == "" {
			continue
		}

		path := filepath.Join(dir, name)
		Register(Hook{
			Name:    hookName,
			Phase:   phase,
			Command: path,
			Timeout: 30,
		})
		log.Printf("[HOOK] Auto-registered: %s → %s", name, phase)
	}
	return nil
}

func parseHookFilename(name string) (Phase, string) {
	phases := []Phase{PhasePreScan, PhasePostDiscovery, PhasePostConfirm, PhasePostExploit, PhasePostReport}
	for _, p := range phases {
		prefix := string(p) + "_"
		if strings.HasPrefix(name, prefix) {
			hookName := strings.TrimPrefix(name, prefix)
			// Strip extension for display name
			ext := filepath.Ext(hookName)
			if ext != "" {
				hookName = hookName[:len(hookName)-len(ext)]
			}
			return p, hookName
		}
	}
	return "", ""
}
