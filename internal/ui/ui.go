// Package ui holds the terminal output and prompt helpers. Normal output goes to
// stdout; progress, warnings and errors go to stderr so `ap ... > file` captures only
// the result.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/hpidcock/ap/internal/logx"
)

var stdin = bufio.NewReader(os.Stdin)

// Every line also goes to the diagnostic log (logx), so a log file carries the whole
// narrative of a run next to the HTTP exchanges.

// Out prints a result line to stdout.
func Out(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
	logx.Debugf("ui", "out: "+format, a...)
}

// Step prints a progress line to stderr.
func Step(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	logx.Debugf("ui", "step: "+format, a...)
}

// Warn prints a warning to stderr.
func Warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", a...)
	logx.Debugf("ui", "warning: "+format, a...)
}

// Err prints an error to stderr.
func Err(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	logx.Debugf("ui", "error: "+format, a...)
}

// Ask reads a trimmed line. The answer is not logged.
func Ask(prompt string) (string, error) {
	logx.Debugf("ui", "prompt: %s", strings.TrimSpace(prompt))
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Secret reads a line without echo.
func Secret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return Ask("")
}

// ConfirmYN is a Yes/No prompt that defaults to No.
func ConfirmYN(prompt string) bool {
	line, err := Ask(prompt)
	if err != nil {
		return false
	}
	l := strings.ToLower(line)
	return l == "y" || l == "yes"
}

// IsTerminal reports whether both stdin and stdout are TTYs.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// StdinIsTerminal reports whether stdin is a TTY.
func StdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
