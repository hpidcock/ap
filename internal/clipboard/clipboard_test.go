package clipboard

import "testing"

func TestOSC52(t *testing.T) {
	t.Setenv("TMUX", "")
	if got, want := OSC52("hunter2"), "\x1b]52;c;aHVudGVyMg==\a"; got != want {
		t.Fatalf("OSC52 = %q, want %q", got, want)
	}
	if got, want := OSC52(""), "\x1b]52;c;\a"; got != want {
		t.Fatalf("OSC52(\"\") = %q, want %q", got, want)
	}
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1,0")
	if got, want := OSC52("hunter2"), "\x1bPtmux;\x1b\x1b]52;c;aHVudGVyMg==\a\x1b\\"; got != want {
		t.Fatalf("OSC52 under tmux = %q, want %q", got, want)
	}
}

func TestByName(t *testing.T) {
	for _, name := range []string{"wl-copy", "xclip", "xsel"} {
		b, ok := ByName(name)
		if !ok || b.Name() != name || !b.Detachable() {
			t.Fatalf("ByName(%q) = %v, %v", name, b, ok)
		}
	}
	if _, ok := ByName("osc52"); ok {
		t.Fatal("ByName(osc52) should not resolve: it is tied to a terminal")
	}
}

func TestDetectFallsBackToOSC52(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	b := Detect(nil)
	if b.Name() != "osc52" || b.Detachable() || b.Readable() {
		t.Fatalf("Detect without a display = %q detachable=%v readable=%v", b.Name(), b.Detachable(), b.Readable())
	}
}
