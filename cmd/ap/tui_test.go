package main

import (
	"reflect"
	"testing"
)

func TestWrapSegments(t *testing.T) {
	segs := []string{"type to filter", "up/down move", "Enter copy password", "Esc clear/quit"}
	if got := wrapSegments(segs, 200); !reflect.DeepEqual(got, []string{"type to filter | up/down move | Enter copy password | Esc clear/quit"}) {
		t.Fatalf("wide: %q", got)
	}
	want := []string{"type to filter | up/down move", "Enter copy password", "Esc clear/quit"}
	if got := wrapSegments(segs, 35); !reflect.DeepEqual(got, want) {
		t.Fatalf("narrow: %q, want %q", got, want)
	}
	if got := wrapSegments(segs, 1); len(got) != len(segs) {
		t.Fatalf("tiny: %q", got)
	}
}

func TestSplitKeys(t *testing.T) {
	cases := map[string][]string{
		"\x1b[B\x14":         {"\x1b[B", "\x14"},             // down arrow then Ctrl-T in one read
		"\x1b[A\x1b[A\x1b[A": {"\x1b[A", "\x1b[A", "\x1b[A"}, // key repeat
		"\x1b[1;5C":          {"\x1b[1;5C"},                  // Ctrl-Right, with parameters
		"\x1bOA\r":           {"\x1bOA", "\r"},               // SS3 arrow then Enter
		"\x1b":               {"\x1b"},                       // lone Esc
		"\x1bx":              {"\x1bx"},                      // Alt-x
		"héllo":              {"h", "é", "l", "l", "o"},      // pasted text, rune by rune
		"\x1b[":              {"\x1b["},                      // truncated sequence
	}
	for in, want := range cases {
		var got []string
		for _, k := range splitKeys([]byte(in)) {
			got = append(got, string(k))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("splitKeys(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFitColumns(t *testing.T) {
	cases := []struct {
		name   string
		widths []int
		fixed  int
		avail  int
		want   []int
	}{
		{"fits", []int{10, 5, 6}, 12, 80, []int{10, 5, 6}},
		{"widest gives way first", []int{30, 10, 6}, 12, 60, []int{26, 10, 6}},
		{"widest levels with runner-up, then both shrink", []int{30, 20, 6}, 12, 44, []int{10, 10, 6}},
		{"otp column is never touched", []int{10, 10, 6}, 12, 20, []int{4, 4, 4}},
		{"no otp column", []int{30, 10, 6}, 0, 40, []int{20, 10, 6}},
		{"columns under colMin are left alone", []int{2, 40, 2}, 0, 20, []int{2, 12, 2}},
	}
	for _, tc := range cases {
		got := fitColumns(tc.widths, tc.fixed, tc.avail)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: fitColumns(%v, %d, %d) = %v, want %v", tc.name, tc.widths, tc.fixed, tc.avail, got, tc.want)
		}
		total := colGap * (len(got) - 1)
		if tc.fixed > 0 {
			total += colGap + tc.fixed
		}
		for _, x := range got {
			total += x
		}
		minTotal := colGap*(len(got)-1) + colMin*len(got)
		if tc.fixed > 0 {
			minTotal += colGap + tc.fixed
		}
		if total > tc.avail && total > minTotal {
			t.Errorf("%s: total %d exceeds %d without hitting the floor", tc.name, total, tc.avail)
		}
	}
}

func TestTruncate(t *testing.T) {
	for in, want := range map[[2]any]string{
		{"short", 10}:      "short",
		{"exactly", 7}:     "exactly",
		{"too long", 5}:    "too …",
		{"héllo wörld", 6}: "héllo…",
		{"ab", 1}:          "a",
		{"ab", 0}:          "",
	} {
		if got := truncate(in[0].(string), in[1].(int)); got != want {
			t.Errorf("truncate(%q, %d) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
