// Package clipboard puts text on the system clipboard. It drives wl-copy on Wayland and
// xclip or xsel on X11, and otherwise emits the OSC 52 escape sequence, which the terminal
// emulator turns into a clipboard write; that path also works over SSH and inside tmux,
// provided the terminal allows it.
package clipboard

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	kindWlCopy = "wl-copy"
	kindXclip  = "xclip"
	kindXsel   = "xsel"
	kindOSC52  = "osc52"
)

// Backend is one way of reaching the clipboard.
type Backend struct {
	kind string
	tty  io.Writer // OSC 52 only: where the escape sequence goes
}

// Detect picks the backend for this environment. tty is the terminal the caller is drawing
// on; it receives OSC 52 sequences when no clipboard tool fits the session.
func Detect(tty io.Writer) *Backend {
	if os.Getenv("WAYLAND_DISPLAY") != "" && have(kindWlCopy) {
		return &Backend{kind: kindWlCopy}
	}
	if os.Getenv("DISPLAY") != "" {
		for _, k := range []string{kindXclip, kindXsel} {
			if have(k) {
				return &Backend{kind: k}
			}
		}
	}
	return &Backend{kind: kindOSC52, tty: tty}
}

// ByName returns the tool backend called name, for a process that did not do the detection
// itself. The OSC 52 backend is tied to a terminal and cannot be named.
func ByName(name string) (*Backend, bool) {
	switch name {
	case kindWlCopy, kindXclip, kindXsel:
		return &Backend{kind: name}, true
	}
	return nil, false
}

// Name is the tool in use, or "osc52".
func (b *Backend) Name() string { return b.kind }

// Describe is a short human-readable description for status lines.
func (b *Backend) Describe() string {
	if b.kind == kindOSC52 {
		return "terminal (OSC 52)"
	}
	return b.kind
}

// Detachable reports whether another process can clear this clipboard later, i.e. the
// backend is a tool rather than the terminal the caller is drawing on.
func (b *Backend) Detachable() bool { return b.kind != kindOSC52 }

// Readable reports whether Read works, so a pending clear can check that the clipboard
// still holds what was copied before wiping it.
func (b *Backend) Readable() bool {
	switch b.kind {
	case kindWlCopy:
		return have("wl-paste")
	case kindXclip, kindXsel:
		return true
	}
	return false
}

// Copy puts text on the clipboard.
func (b *Backend) Copy(text string) error {
	switch b.kind {
	case kindWlCopy:
		return run(strings.NewReader(text), "wl-copy")
	case kindXclip:
		return run(strings.NewReader(text), "xclip", "-selection", "clipboard", "-in")
	case kindXsel:
		return run(strings.NewReader(text), "xsel", "--clipboard", "--input")
	default:
		_, err := io.WriteString(b.tty, OSC52(text))
		return err
	}
}

// Clear empties the clipboard.
func (b *Backend) Clear() error {
	switch b.kind {
	case kindWlCopy:
		return run(nil, "wl-copy", "--clear")
	case kindXclip:
		return run(strings.NewReader(""), "xclip", "-selection", "clipboard", "-in")
	case kindXsel:
		return run(nil, "xsel", "--clipboard", "--clear")
	default:
		_, err := io.WriteString(b.tty, OSC52(""))
		return err
	}
}

// Read returns the clipboard text. ok is false when this backend cannot read it back.
func (b *Backend) Read() (text string, ok bool) {
	var args []string
	switch b.kind {
	case kindWlCopy:
		if !have("wl-paste") {
			return "", false
		}
		args = []string{"wl-paste", "--no-newline"}
	case kindXclip:
		args = []string{"xclip", "-selection", "clipboard", "-out"}
	case kindXsel:
		args = []string{"xsel", "--clipboard", "--output"}
	default:
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	if err != nil {
		// An empty clipboard is reported as a failure by every one of these tools; a
		// timeout means we genuinely could not read it.
		return "", ctx.Err() == nil
	}
	return string(out), true
}

// OSC52 is the escape sequence that asks the terminal to put text on the clipboard,
// wrapped for tmux passthrough when running under tmux. An empty text clears it.
func OSC52(text string) string {
	seq := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\a"
	if os.Getenv("TMUX") != "" {
		seq = "\x1bPtmux;" + strings.ReplaceAll(seq, "\x1b", "\x1b\x1b") + "\x1b\\"
	}
	return seq
}

func have(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// run executes a clipboard tool with stdin as its input. Nothing of ours is attached to its
// stdout or stderr: wl-copy and xclip fork a server that outlives the call to serve pastes,
// and it would inherit any pipe and keep Wait blocked for as long as the clipboard holds.
func run(stdin io.Reader, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s: timed out", name)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
