package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"

	"github.com/hpidcock/ap/internal/vault"
)

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

// runTUI is a very basic full-screen browser: status header, live-filter search box,
// and reveal a selected password with Enter. Type to filter, up/down to move, Esc to
// clear the query (or quit when it is empty).
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

	creds := store.All()
	sort.SliceStable(creds, func(i, j int) bool {
		a, b := creds[i], creds[j]
		if strings.ToLower(a.Title) != strings.ToLower(b.Title) {
			return strings.ToLower(a.Title) < strings.ToLower(b.Title)
		}
		return strings.ToLower(a.Username) < strings.ToLower(b.Username)
	})
	domW, userW := 6, 4
	for _, c := range creds {
		domW = max(domW, len(c.Domain))
		userW = max(userW, len(c.Username))
	}
	domW, userW = min(domW, 32), min(userW, 32)
	summary := printable(fmt.Sprintf("%s  |  %d credential(s)", statusSummary(), len(creds)))
	footer := "type to search | up/down move | Enter reveal | Esc clear/quit"

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
		w, h, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil || w <= 0 || h <= 0 {
			w, h = 80, 24
		}
		viewH := max(1, h-4)
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
		if len(shown) == 0 {
			put(3, "(no matching credentials)", "\x1b[2m")
		}
		for idx := 0; idx < viewH && offset+idx < len(shown); idx++ {
			i := shown[offset+idx]
			c := creds[i]
			pw := "******"
			if revealed[i] {
				pw = c.Password
			}
			line := printable(fmt.Sprintf("%-*s  %-*s  %s%s", domW, c.Domain, userW, c.Username, pw, totpSuffix(c)))
			attr := ""
			if offset+idx == sel {
				attr = "\x1b[7m"
			}
			put(3+idx, line, attr)
		}
		put(h-1, footer, "\x1b[2m")
		out.Flush()

		select {
		case <-ticker.C:
			continue
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			switch {
			case len(k) == 1 && k[0] == 27: // Esc
				if query != "" {
					query, sel, offset = "", 0, 0
				} else {
					return nil
				}
			case len(k) == 1 && (k[0] == 3 || k[0] == 4): // Ctrl-C / Ctrl-D
				return nil
			case string(k) == "\x1b[A":
				if sel > 0 {
					sel--
				}
			case string(k) == "\x1b[B":
				if sel < len(shown)-1 {
					sel++
				}
			case len(k) == 1 && (k[0] == '\r' || k[0] == '\n'):
				if len(shown) > 0 {
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
	}
}
