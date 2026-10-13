// Package hostinstall registers the native-messaging host with Chromium-family browsers
// and Firefox by writing a host manifest into each browser's NativeMessagingHosts dir.
package hostinstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// HostName must match the HOST constant in extension/background.js.
const HostName = "io.github.hpidcock.ap"

// GeckoID must match browser_specific_settings.gecko.id in extension/manifest.json.
const GeckoID = "ap@hpidcock.github.io"

// ChromiumDirs are the NativeMessagingHosts directories, relative to $HOME, of the
// Chromium-family browsers we know about.
var ChromiumDirs = []string{
	".config/google-chrome/NativeMessagingHosts",
	".config/chromium/NativeMessagingHosts",
	".config/helium/NativeMessagingHosts",
	".config/net.imput.helium/NativeMessagingHosts",
	".config/BraveSoftware/Brave-Browser/NativeMessagingHosts",
	".config/microsoft-edge/NativeMessagingHosts",
	".config/vivaldi/NativeMessagingHosts",
}

// ChromiumManifest is the manifest for a Chromium-family browser.
func ChromiumManifest(hostPath, extensionID string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"name":            HostName,
		"description":     "Apple Passwords native messaging host (ap)",
		"path":            hostPath,
		"type":            "stdio",
		"allowed_origins": []string{"chrome-extension://" + extensionID + "/"},
	}, "", "  ")
}

// FirefoxManifest is the manifest for Firefox-family browsers.
func FirefoxManifest(hostPath string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"name":               HostName,
		"description":        "Apple Passwords native messaging host (ap)",
		"path":               hostPath,
		"type":               "stdio",
		"allowed_extensions": []string{GeckoID},
	}, "", "  ")
}

// Install writes the manifests. Browsers whose config dir is absent are skipped. Returns
// the paths written.
func Install(hostPath, extensionID string, log func(string)) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	var written []string
	write := func(dir string, manifest []byte) error {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		p := filepath.Join(dir, HostName+".json")
		if err := os.WriteFile(p, append(manifest, '\n'), 0o644); err != nil {
			return err
		}
		written = append(written, p)
		return nil
	}
	if extensionID != "" {
		manifest, err := ChromiumManifest(hostPath, extensionID)
		if err != nil {
			return nil, err
		}
		for _, rel := range ChromiumDirs {
			dir := filepath.Join(home, rel)
			if _, err := os.Stat(filepath.Dir(dir)); err != nil {
				continue // browser not installed
			}
			if err := write(dir, manifest); err != nil {
				return written, err
			}
		}
	} else if log != nil {
		log("No Chromium extension id given; skipping Chromium-family browsers (pass it to enable).")
	}
	ff, err := FirefoxManifest(hostPath)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("firefox"); err == nil || exists(filepath.Join(home, ".mozilla")) {
		if err := write(filepath.Join(home, ".mozilla", "native-messaging-hosts"), ff); err != nil {
			return written, err
		}
	}
	if _, err := exec.LookPath("librewolf"); err == nil || exists(filepath.Join(home, ".librewolf")) {
		if err := write(filepath.Join(home, ".librewolf", "native-messaging-hosts"), ff); err != nil {
			return written, err
		}
	}
	if len(written) == 0 {
		return nil, errors.New("no supported browser config dir found; nothing installed")
	}
	return written, nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// HostBinary locates the ap-host binary: next to the running executable, else on PATH.
func HostBinary() (string, error) {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "ap-host")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return filepath.EvalSymlinks(cand)
		}
	}
	p, err := exec.LookPath("ap-host")
	if err != nil {
		return "", fmt.Errorf("ap-host binary not found next to ap or on PATH")
	}
	return filepath.Abs(p)
}
