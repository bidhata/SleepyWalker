package sqlmap

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"sleepywalker/internal/config"
	"sleepywalker/internal/scanner"
)

// WAFTamperMap maps WAF names to recommended sqlmap tamper scripts.
var WAFTamperMap = map[string]string{
	"Cloudflare":        "between,randomcase,space2comment",
	"AWS WAF":           "charencode,randomcase,space2comment",
	"ModSecurity":       "between,randomcase,space2comment,charencode",
	"Imperva/Incapsula": "charencode,space2mssqlblank,randomcase",
	"Akamai":            "between,space2tab,randomcase",
	"F5 BIG-IP ASM":     "space2comment,randomcase,between",
	"Sucuri":            "charencode,randomcase,space2comment",
	"Barracuda":         "space2comment,randomcase,charencode",
	"Generic WAF":       "between,randomcase,space2comment,charencode",
	"Unknown WAF":       "between,randomcase,space2comment",
}

func resolveSQLMap(cfg config.Config) (exe string, prefixArgs []string, err error) {
	if cfg.SQLMapPath != "" {
		if strings.HasSuffix(strings.ToLower(cfg.SQLMapPath), ".py") {
			py, pyErr := findPython()
			if pyErr != nil {
				return "", nil, fmt.Errorf("sqlmap path %q is a .py file but no python found: %w", cfg.SQLMapPath, pyErr)
			}
			return py, []string{cfg.SQLMapPath}, nil
		}
		return cfg.SQLMapPath, nil, nil
	}

	if path, lookErr := exec.LookPath("sqlmap"); lookErr == nil {
		return path, nil, nil
	}

	if path, lookErr := exec.LookPath("sqlmap.py"); lookErr == nil {
		if py, pyErr := findPython(); pyErr == nil {
			return py, []string{path}, nil
		}
	}

	return "", nil, fmt.Errorf(
		"sqlmap not found in PATH.\n" +
			"Install with: pip install sqlmap\n" +
			"Or pass -sqlmap-path /path/to/sqlmap.py")
}

func findPython() (string, error) {
	candidates := []string{"python3", "python", "py"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "py", "python3"}
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no python interpreter found")
}

// RunSQLMap executes sqlmap against a given entry point with full config forwarding.
func RunSQLMap(cfg config.Config, ep scanner.EntryPoint, payload string, outputDir string, wafName string) ([]string, error) {
	exe, prefixArgs, err := resolveSQLMap(cfg)
	if err != nil {
		return nil, err
	}

	targetURL := ep.URL

	// Fix #15: use SHA-256 instead of MD5 to avoid hash collisions between
	// different endpoints mapping to the same output directory.
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", ep.Method, targetURL, ep.InjectionLoc)))
	epHash := fmt.Sprintf("%x", sum[:8]) // 16 hex chars — collision-free in practice
	epDir := filepath.Join(outputDir, epHash)
	if err := os.MkdirAll(epDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create sqlmap output dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := append(prefixArgs, "-u", targetURL, "--batch", "--dump", "--output-dir", epDir)
	args = append(args, "--threads", fmt.Sprintf("%d", cfg.Threads))

	risk := cfg.SQLMapRisk
	if risk < 1 || risk > 3 {
		risk = 2
	}
	level := cfg.SQLMapLevel
	if level < 1 || level > 5 {
		level = 3
	}
	args = append(args, "--risk", fmt.Sprintf("%d", risk), "--level", fmt.Sprintf("%d", level))

	if cfg.Cookies != "" {
		args = append(args, "--cookie", cfg.Cookies)
	}
	if cfg.ProxyURL != "" {
		args = append(args, "--proxy", cfg.ProxyURL)
	}
	for _, h := range cfg.ExtraHeaders {
		args = append(args, "--header", h)
	}

	if ep.Method == "POST" && len(ep.Params) > 0 {
		form := url.Values{}
		for k, v := range ep.Params {
			if v == "" {
				v = "1"
			}
			form.Set(k, v)
		}
		args = append(args, "--data", form.Encode(), "--method", "POST")
	}

	if wafName != "" {
		if tamper, ok := WAFTamperMap[wafName]; ok {
			args = append(args, "--tamper", tamper)
			log.Printf("[SQLMAP] Auto-selected tamper scripts for %s: %s", wafName, tamper)
		}
	}

	log.Printf("[SQLMAP] Executing: %s %s", exe, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, exe, args...)
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("sqlmap timeout (5 min) for %s", targetURL)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlmap error: %w\nOutput:\n%s", err, string(out))
	}

	// Fix #12: guard info nil before calling info.IsDir() — walkErr non-nil means info is nil.
	var dumps []string
	filepath.Walk(epDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".sql" || ext == ".csv" || ext == ".sqlite" {
			dumps = append(dumps, path)
		}
		return nil
	})

	if len(dumps) == 0 {
		return nil, fmt.Errorf("no dump files produced for %s", targetURL)
	}
	return dumps, nil
}
