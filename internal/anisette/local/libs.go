package local

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// APKURL is Apple's public Apple Music for Android download.
const APKURL = "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk"

// LibraryNames are the two native libraries ADI needs.
var LibraryNames = []string{"libCoreADI.so", "libstoreservicescore.so"}

func apkArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "arm64-v8a", nil
	}
	return "", fmt.Errorf("anisette: architecture %s is not supported", runtime.GOARCH)
}

// LibrariesPresent reports whether both libraries are in dir.
func LibrariesPresent(dir string) bool {
	for _, n := range LibraryNames {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			return false
		}
	}
	return true
}

// EnsureLibraries downloads the APK and extracts the libraries into dir if missing.
func EnsureLibraries(dir string, logf func(string, ...any)) error {
	if LibrariesPresent(dir) {
		return nil
	}
	arch, err := apkArch()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if logf == nil {
		logf = log.Printf
	}
	logf("downloading Apple's ADI libraries from %s ...", APKURL)
	tmp, err := os.CreateTemp(dir, "applemusic-*.apk")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(APKURL)
	if err != nil {
		return fmt.Errorf("anisette: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("anisette: download: HTTP %d", resp.StatusCode)
	}
	size, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return fmt.Errorf("anisette: download: %w", err)
	}
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return fmt.Errorf("anisette: apk is not a zip: %w", err)
	}
	for _, name := range LibraryNames {
		want := "lib/" + arch + "/" + name
		var found *zip.File
		for _, f := range zr.File {
			if f.Name == want {
				found = f
				break
			}
		}
		if found == nil {
			return fmt.Errorf("anisette: %s not found in the APK", want)
		}
		rc, err := found.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	if !LibrariesPresent(dir) {
		return errors.New("anisette: library extraction failed")
	}
	logf("done.")
	return nil
}
