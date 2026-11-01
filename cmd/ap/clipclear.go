package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hpidcock/ap/internal/clipboard"
	"github.com/hpidcock/ap/internal/logx"
)

func hashSecret(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// spawnClipClear starts a detached `ap __clip-clear` that wipes the clipboard after d if
// it still holds text. Only a hash of text crosses the process boundary, over stdin.
func spawnClipClear(backend, text string, d time.Duration) {
	exe, err := os.Executable()
	if err != nil {
		logx.Errorf("clip", err, "cannot locate ap binary for the clipboard clear")
		return
	}
	cmd := exec.Command(exe, "__clip-clear", backend, strconv.Itoa(int(d.Round(time.Second)/time.Second)))
	cmd.Stdin = strings.NewReader(hashSecret(text) + "\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logx.Errorf("clip", err, "cannot start the clipboard clear")
		return
	}
	_ = cmd.Process.Release()
}

// cmdClipClear is the hidden helper behind spawnClipClear: `ap __clip-clear BACKEND SECONDS`
// with the sha256 of the copied text on stdin. It sleeps, then clears the clipboard unless
// something else has been copied since.
func cmdClipClear(args []string) (int, error) {
	if len(args) != 2 {
		return 2, fmt.Errorf("usage: ap __clip-clear BACKEND SECONDS")
	}
	b, ok := clipboard.ByName(args[0])
	if !ok {
		return 2, fmt.Errorf("unknown clipboard backend %q", args[0])
	}
	secs, err := strconv.Atoi(args[1])
	if err != nil || secs < 0 {
		return 2, fmt.Errorf("bad delay %q", args[1])
	}
	want, err := io.ReadAll(io.LimitReader(os.Stdin, 128))
	if err != nil {
		return 1, err
	}
	time.Sleep(time.Duration(secs) * time.Second)
	if cur, ok := b.Read(); ok && hashSecret(cur) != strings.TrimSpace(string(want)) {
		logx.Debugf("clip", "clipboard changed since the copy; leaving it alone")
		return 0, nil
	}
	if err := b.Clear(); err != nil {
		return 1, err
	}
	logx.Debugf("clip", "clipboard cleared via %s", b.Name())
	return 0, nil
}
