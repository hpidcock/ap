package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/hpidcock/ap/internal/clipboard"
	"github.com/hpidcock/ap/internal/totp"
	"github.com/hpidcock/ap/internal/vault"
)

// clipboardTTL is how long a copied secret stays on the clipboard before ap clears it,
// unless something else has been copied over it in the meantime.
const clipboardTTL = 45 * time.Second

// printable replaces non-printable runes with a dot so untrusted values (passwords are
// arbitrary; some keychain items are cert/key blobs full of control bytes) can't inject
// terminal escape sequences.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

func clip(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	return string(r[:w])
}

// wrapSegments packs " | "-separated help segments into as few lines as fit in w columns.
func wrapSegments(segs []string, w int) []string {
	var lines []string
	cur := ""
	for _, s := range segs {
		switch {
		case cur == "":
			cur = s
		case len(cur)+3+len(s) <= w:
			cur += " | " + s
		default:
			lines = append(lines, cur)
			cur = s
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// colGap is the space between columns; colMin is the narrowest a column is squeezed to.
const colGap, colMin = 2, 4

// fitColumns squeezes the text columns into avail cells, leaving room for a fixed-width
// trailing column (the verification code, never truncated). The widest column gives way
// first, until it is level with the next widest, and so on; nothing goes below colMin.
func fitColumns(widths []int, fixed, avail int) []int {
	fit := append([]int{}, widths...)
	total := func() int {
		t := colGap * (len(fit) - 1)
		if fixed > 0 {
			t += colGap + fixed
		}
		for _, x := range fit {
			t += x
		}
		return t
	}
	for total() > avail {
		k := -1 // the widest column still above the floor; ties shrink in turn
		for j, x := range fit {
			if x > colMin && (k < 0 || x > fit[k]) {
				k = j
			}
		}
		if k < 0 {
			break
		}
		fit[k]--
	}
	return fit
}

// truncate cuts s to w cells, marking the cut with an ellipsis.
func truncate(s string, w int) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w <= 1 {
		return clip(s, w)
	}
	return string(r[:w-1]) + "…"
}

// splitKeys cuts one terminal read into individual key presses: a CSI sequence such as
// an arrow key, an Alt+key pair, or a single rune. Key repeat and pasted text arrive
// coalesced in one read, and dropping the chunk would make the arrows feel stuck.
func splitKeys(b []byte) [][]byte {
	var keys [][]byte
	for len(b) > 0 {
		n := 1
		switch {
		case b[0] == 0x1b && len(b) >= 3 && b[1] == '[':
			n = 2
			for n < len(b) && (b[n] < 0x40 || b[n] > 0x7e) { // parameter and intermediate bytes
				n++
			}
			if n < len(b) {
				n++ // final byte
			}
		case b[0] == 0x1b && len(b) >= 3 && b[1] == 'O':
			n = 3
		case b[0] == 0x1b && len(b) >= 2 && b[1] >= 0x20 && b[1] < 0x7f:
			n = 2 // Alt+key
		case b[0] >= 0x80:
			_, n = utf8.DecodeRune(b)
		}
		keys = append(keys, b[:n])
		b = b[n:]
	}
	return keys
}

// clipState tracks the secret ap last put on the clipboard so it can be wiped again.
type clipState struct {
	backend  *clipboard.Backend
	text     string // what was copied; "" when nothing is pending
	deadline time.Time
}

// copy puts text on the clipboard and arms the clear timer. It returns the status text.
func (c *clipState) copy(what, text string) string {
	if err := c.backend.Copy(text); err != nil {
		c.text = ""
		return "copy failed: " + err.Error()
	}
	c.text, c.deadline = text, time.Now().Add(clipboardTTL)
	return "copied " + what
}

// expire clears the clipboard once the deadline has passed, unless the user has since
// copied something else over it. It returns a status note when it did something.
func (c *clipState) expire(now time.Time) string {
	if c.text == "" || now.Before(c.deadline) {
		return ""
	}
	defer func() { c.text = "" }()
	if cur, ok := c.backend.Read(); ok && cur != c.text {
		return ""
	}
	if err := c.backend.Clear(); err != nil {
		return "clipboard clear failed: " + err.Error()
	}
	return "clipboard cleared"
}

// detach hands a pending clear to a background `ap __clip-clear` process so the secret is
// still wiped after the TUI exits. The terminal (OSC 52) backend cannot be reached from
// another process, so that case is left alone.
func (c *clipState) detach() {
	if c.text == "" || !c.backend.Detachable() {
		return
	}
	left := time.Until(c.deadline)
	if left < time.Second {
		left = time.Second
	}
	spawnClipClear(c.backend.Name(), c.text, left)
}

// runTUI is a very basic full-screen browser: status header, live-filter search box, and
// the selected credential's password goes to the clipboard with Enter. Type to filter,
// up/down to move, Tab to reveal, Esc to clear the query (or quit when it is empty).
func runTUI(store *vault.Store) error {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, oldState)
	out := bufio.NewWriter(os.Stdout)
	defer func() {
		fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
		out.Flush()
	}()
	fmt.Fprint(out, "\x1b[?1049h\x1b[?25l")

	cb := &clipState{backend: clipboard.Detect(out)}
	defer cb.detach()

	creds := store.All()
	sort.SliceStable(creds, func(i, j int) bool {
		a, b := creds[i], creds[j]
		if strings.ToLower(a.Title) != strings.ToLower(b.Title) {
			return strings.ToLower(a.Title) < strings.ToLower(b.Title)
		}
		return strings.ToLower(a.Username) < strings.ToLower(b.Username)
	})
	summary := printable(fmt.Sprintf("%s  |  %d credential(s)  |  clipboard: %s", statusSummary(), len(creds), cb.backend.Describe()))
	helpSegs := []string{"type to filter", "up/down move", "Enter copy password", "^U copy username", "^T copy code", "Tab reveal", "Esc clear/quit"}

	keys := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			keys <- append([]byte{}, buf[:n]...)
		}
	}()

	query, sel, offset := "", 0, 0
	revealed := map[int]bool{}
	note := "" // transient status, replaced by the next action
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var shown []int
		for i, c := range creds {
			if matchCred(c, strings.ToLower(query)) {
				shown = append(shown, i)
			}
		}
		if sel > len(shown)-1 {
			sel = len(shown) - 1
		}
		if sel < 0 {
			sel = 0
		}
		now := time.Now()
		if n := cb.expire(now); n != "" {
			note = n
		}
		w, h, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil || w <= 0 || h <= 0 {
			w, h = 80, 24
		}
		help := wrapSegments(helpSegs, w-1)
		viewH := max(1, h-3-len(help))
		if sel < offset {
			offset = sel
		} else if sel >= offset+viewH {
			offset = sel - viewH + 1
		}
		put := func(y int, s string, attr string) {
			fmt.Fprintf(out, "\x1b[%d;1H\x1b[2K%s%s\x1b[0m", y+1, attr, clip(s, w-1))
		}
		fmt.Fprint(out, "\x1b[2J")
		put(0, summary, "\x1b[1m")
		put(1, printable("Search: "+query), "")
		status := note
		if cb.text != "" {
			left := max(0, int(cb.deadline.Sub(now).Round(time.Second)/time.Second))
			status = fmt.Sprintf("%s  -  clipboard clears in %ds", note, left)
		}
		put(2, printable(status), "\x1b[33m")
		if len(shown) == 0 {
			put(3, "(no matching credentials)", "\x1b[2m")
		}
		// Columns are sized to the longest matching value (not just the visible rows, so
		// scrolling doesn't shift them) and squeezed to the terminal width, widest first.
		cells := make([][4]string, len(shown))
		var widths [4]int
		for n, i := range shown {
			c := creds[i]
			pw := "******"
			if revealed[i] {
				pw = c.Password
			}
			otp, otpW := totpCell(c)
			cells[n] = [4]string{printable(c.Domain), printable(c.Username), printable(pw), otp}
			for j, s := range cells[n][:3] {
				widths[j] = max(widths[j], utf8.RuneCountInString(s))
			}
			widths[3] = max(widths[3], otpW)
		}
		fit := fitColumns(widths[:3], widths[3], w-1)
		for idx := 0; idx < viewH && offset+idx < len(shown); idx++ {
			row := cells[offset+idx]
			line := fmt.Sprintf("%-*s  %-*s  %-*s", fit[0], truncate(row[0], fit[0]), fit[1], truncate(row[1], fit[1]), fit[2], truncate(row[2], fit[2]))
			if widths[3] > 0 {
				line += "  " + row[3]
			}
			attr := ""
			if offset+idx == sel {
				attr = "\x1b[7m"
			}
			put(3+idx, line, attr)
		}
		for i, line := range help {
			put(h-len(help)+i, line, "\x1b[2m")
		}
		out.Flush()

		select {
		case <-ticker.C:
			continue
		case chunk, ok := <-keys:
			if !ok {
				return nil
			}
			quit := false
			for _, k := range splitKeys(chunk) {
				var cur *vault.Credential // the selection, re-read per key: arrows move it
				if len(shown) > 0 {
					cur = &creds[shown[sel]]
				}
				label := func(what string) string {
					return fmt.Sprintf("%s for %s (%s)", what, cur.Domain, cur.Username)
				}
				switch {
				case len(k) == 1 && k[0] == 27: // Esc
					if query != "" {
						query, sel, offset = "", 0, 0
					} else {
						quit = true
					}
				case len(k) == 1 && (k[0] == 3 || k[0] == 4): // Ctrl-C / Ctrl-D
					quit = true
				case string(k) == "\x1b[A":
					if sel > 0 {
						sel--
					}
				case string(k) == "\x1b[B":
					if sel < len(shown)-1 {
						sel++
					}
				case len(k) == 1 && (k[0] == '\r' || k[0] == '\n'): // Enter
					if cur != nil {
						note = cb.copy(label("password"), cur.Password)
					}
				case len(k) == 1 && k[0] == 0x15: // Ctrl-U
					if cur != nil {
						note = cb.copy(label("username"), cur.Username)
					}
				case len(k) == 1 && k[0] == 0x14: // Ctrl-T
					if cur != nil {
						if code := totp.Generate(cur.TOTP); code != nil {
							note = cb.copy(label("verification code"), code.Code)
						} else {
							note = "no verification code for " + cur.Domain
						}
					}
				case len(k) == 1 && k[0] == '\t': // Tab
					if cur != nil {
						revealed[shown[sel]] = !revealed[shown[sel]]
					}
				case len(k) == 1 && (k[0] == 127 || k[0] == 8):
					if query != "" {
						r := []rune(query)
						query = string(r[:len(r)-1])
					}
					sel, offset = 0, 0
				default:
					s := string(k)
					if !strings.HasPrefix(s, "\x1b") {
						for _, r := range s {
							if unicode.IsPrint(r) {
								query += string(r)
							}
						}
						sel, offset = 0, 0
					}
				}
			}
			if quit {
				return nil
			}
		}
	}
}
