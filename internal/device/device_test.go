package device

import "testing"

func TestDescriptionOf(t *testing.T) {
	cases := map[string]string{
		"<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>": "<PC> <Windows;6.2(0,0);9200>",
		"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>":   "<MacBookPro13,2> <macOS;13.1;22C65>",
		"<only-one>": "",
		"":           "",
	}
	for in, want := range cases {
		if got := DescriptionOf(in); got != want {
			t.Errorf("DescriptionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetClientInfo(t *testing.T) {
	defer func() { gsaClientInfo, gsaUserAgent, Description = "", "", "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>" }()
	SetClientInfo("<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>", "akd/1.0 CFNetwork/808.1.4")
	if GSAClientInfo() != "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>" || GSAUserAgent() != "akd/1.0 CFNetwork/808.1.4" {
		t.Fatalf("gsa: %q %q", GSAClientInfo(), GSAUserAgent())
	}
	if Description != "<PC> <Windows;6.2(0,0);9200>" {
		t.Fatalf("description: %q", Description)
	}
}
