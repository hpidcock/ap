// Command ap-host is the native-messaging host the browser extension talks to. The
// browser execs it with the extension's stdio; it answers domain queries from the
// decrypted vault, read-only, and never touches the network itself.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/hpidcock/ap/internal/hme"
	"github.com/hpidcock/ap/internal/paths"
	"github.com/hpidcock/ap/internal/vault"
)

// maybeTriggerSync kicks off a detached `ap sync` when the vault is older than
// AP_SYNC_MAX_AGE (default 6h). Best-effort: never blocks and never fails the host. A
// debounce marker stops a multi-frame page from launching many syncs; `ap sync` itself
// holds a lock so only one ever runs.
func maybeTriggerSync() {
	maxAge := int64(6 * 3600)
	if v := os.Getenv("AP_SYNC_MAX_AGE"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return
		}
		maxAge = n
	}
	if maxAge <= 0 {
		return
	}
	if st, err := os.Stat(paths.VaultFile()); err == nil && time.Since(st.ModTime()) < time.Duration(maxAge)*time.Second {
		return
	}
	attempt := paths.SyncAttemptFile()
	if st, err := os.Stat(attempt); err == nil && time.Since(st.ModTime()) < 5*time.Minute {
		return
	}
	_ = os.WriteFile(attempt, nil, 0o600)
	now := time.Now()
	_ = os.Chtimes(attempt, now, now)
	ap := "ap"
	if exe, err := os.Executable(); err == nil {
		if cand := filepath.Join(filepath.Dir(exe), "ap"); fileExists(cand) {
			ap = cand
		}
	}
	cmd := exec.Command(ap, "sync")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err == nil {
		_ = cmd.Process.Release()
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func main() {
	maybeTriggerSync()
	store, err := vault.LoadVault()
	if err != nil || store == nil {
		store = vault.NewStore(nil)
	}
	aliases, err := hme.LoadAliases()
	if err != nil {
		aliases = nil
	}
	if err := vault.Serve(store, aliases, os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
