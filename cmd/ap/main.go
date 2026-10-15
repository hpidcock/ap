// Command ap is an unofficial iCloud Keychain client for Linux. Sign in with your Apple
// ID and ap registers this computer as one of your Apple devices, joins your keychain,
// and downloads your passwords into a private, encrypted vault that the bundled browser
// extension fills from. It also embeds the anisette server Apple's sign-in requires.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hpidcock/ap/internal/anisette"
	"github.com/hpidcock/ap/internal/anisette/local"
	"github.com/hpidcock/ap/internal/anisette/remote"
	"github.com/hpidcock/ap/internal/cloudkit"
	"github.com/hpidcock/ap/internal/device"
	"github.com/hpidcock/ap/internal/gsa"
	"github.com/hpidcock/ap/internal/hme"
	"github.com/hpidcock/ap/internal/hostinstall"
	"github.com/hpidcock/ap/internal/icloud"
	"github.com/hpidcock/ap/internal/logx"
	"github.com/hpidcock/ap/internal/octagon"
	"github.com/hpidcock/ap/internal/paths"
	"github.com/hpidcock/ap/internal/plistx"
	"github.com/hpidcock/ap/internal/session"
	"github.com/hpidcock/ap/internal/totp"
	"github.com/hpidcock/ap/internal/ui"
	"github.com/hpidcock/ap/internal/vault"
	"github.com/hpidcock/ap/internal/webauth"
)

const icloudAuthToken = "com.apple.gs.icloud.auth"

func usage() {
	fmt.Fprintf(os.Stderr, `ap - unofficial iCloud Keychain client for Linux (read-only)

Usage: ap <command> [options]

Commands:
  login         sign in, join your iCloud Keychain, and download your passwords
  show          browse and search your passwords and Hide My Email addresses
  sync          refresh your passwords now
  logout        sign out (use --wipe-device to also forget this device)
  install-host  register the browser extension's native-messaging host

Machine data (accepted anywhere on the command line, remembered for later runs):
  --anisette URL    use this anisette-v3 server (default: `+remote.DefaultURL+`)
  --anisette local  generate the machine data in-process with Apple's Android library
                    (blocked by Apple since 2026-10-15; kept for when that changes)
  AP_ANISETTE does the same from the environment

Diagnostics (accepted anywhere on the command line):
  --debug           log every step and Apple exchange to stderr (secrets redacted)
  --trace           like --debug, plus request and response bodies
  --log-file PATH   append the full trace to PATH (0600) whether or not --debug is set
  AP_DEBUG=1|2 and AP_LOG_FILE=PATH do the same from the environment (also for ap-host)
`)
}

// anisetteChoice is --anisette / AP_ANISETTE for this run ("" = remembered or default).
var anisetteChoice string

// globalFlags pulls the diagnostic and provider flags out of args wherever they appear,
// so that both `ap --debug login` and `ap login --debug` work, and merges them with the
// environment.
func globalFlags(args []string) (rest []string, level logx.Level, logFile string) {
	level = logx.ParseLevel(os.Getenv("AP_DEBUG"))
	logFile = os.Getenv("AP_LOG_FILE")
	anisetteChoice = os.Getenv("AP_ANISETTE")
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--anisette=") || strings.HasPrefix(a, "-anisette="):
			anisetteChoice = a[strings.Index(a, "=")+1:]
		case (a == "--anisette" || a == "-anisette") && i+1 < len(args):
			anisetteChoice = args[i+1]
			i++
		case a == "--debug" || a == "-debug" || a == "-v":
			if level < logx.Debug {
				level = logx.Debug
			}
		case a == "--trace" || a == "-trace" || a == "-vv":
			level = logx.Trace
		case strings.HasPrefix(a, "--log-file=") || strings.HasPrefix(a, "-log-file="):
			logFile = a[strings.Index(a, "=")+1:]
		case (a == "--log-file" || a == "-log-file") && i+1 < len(args):
			logFile = args[i+1]
			i++
		default:
			rest = append(rest, a)
		}
	}
	return rest, level, logFile
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	args, level, logFile := globalFlags(args)
	if err := logx.Init(level, logFile); err != nil {
		ui.Err("%v", err)
		return 2
	}
	defer logx.Close()
	cfgDir, _ := paths.ConfigDir()
	logx.Debugf("ap", "ap starting: args=%v %s config=%s log-level=%d", args, runtime.Version(), cfgDir, level)
	global := flag.NewFlagSet("ap", flag.ContinueOnError)
	global.Usage = usage
	if err := global.Parse(args); err != nil {
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		usage()
		return 2
	}
	cmd, cmdArgs := rest[0], rest[1:]
	var rc int
	var err error
	switch cmd {
	case "login":
		rc, err = cmdLogin(cmdArgs)
	case "show":
		rc, err = cmdShow(cmdArgs)
	case "sync":
		rc, err = cmdSync(cmdArgs)
	case "logout":
		rc, err = cmdLogout(cmdArgs)
	case "install-host":
		rc, err = cmdInstallHost(cmdArgs)
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		ui.Err("unknown command %q", cmd)
		usage()
		return 2
	}
	if err != nil {
		ui.Err("%v", err)
		logx.Errorf("ap", err, "%s failed", cmd)
		if !logx.Enabled() {
			ui.Step("(re-run with --debug for a full trace, or --log-file PATH to save one)")
		}
		if rc == 0 {
			rc = 1
		}
	}
	logx.Debugf("ap", "%s finished rc=%d after %s", cmd, rc, logx.Elapsed())
	return rc
}

// provider returns the anisette machine-data source. The choice (--anisette, AP_ANISETTE)
// is remembered in the config directory so `ap sync` from the timer follows it; with
// nothing chosen the default anisette-v3 server is used. The provider also decides the
// client info every Apple request carries.
func provider() anisette.Provider {
	logf := func(format string, a ...any) { ui.Step(format, a...) }
	choice := anisetteChoice
	if choice != "" {
		if err := saveAnisetteChoice(choice); err != nil {
			ui.Warn("could not remember the anisette choice: %v", err)
		}
	} else {
		choice = loadAnisetteChoice()
	}
	if choice == "" {
		choice = remote.DefaultURL
	}
	var anis anisette.Provider
	if choice == "local" {
		anis = local.NewLocal(paths.AnisetteDir(), logf)
	} else {
		if !strings.HasPrefix(choice, "http://") && !strings.HasPrefix(choice, "https://") {
			choice = "https://" + choice
		}
		anis = remote.New(choice, paths.RemoteAnisetteFile(), logf)
	}
	logx.Debugf("anisette", "provider: %s", choice)
	if ci, ok := anis.(anisette.ClientInfoProvider); ok {
		info, ua, err := ci.ClientInfo()
		if err != nil {
			ui.Warn("could not learn the client info from the anisette provider: %v", err)
		} else {
			device.SetClientInfo(info, ua)
			logx.Debugf("anisette", "client info %q user agent %q -> device description %q", info, ua, device.Description)
		}
	}
	return anis
}

type anisetteConfig struct {
	Provider string `json:"provider"` // "local" or a server URL
}

func loadAnisetteChoice() string {
	data, err := os.ReadFile(paths.AnisetteConfigFile())
	if err != nil {
		return ""
	}
	var cfg anisetteConfig
	if json.Unmarshal(data, &cfg) != nil {
		return ""
	}
	return cfg.Provider
}

func saveAnisetteChoice(choice string) error {
	if loadAnisetteChoice() == choice {
		return nil
	}
	data, _ := json.MarshalIndent(anisetteConfig{Provider: choice}, "", "  ")
	return paths.WritePrivate(paths.AnisetteConfigFile(), data)
}

func twoFAPrompt(kind string) (string, error) {
	where := "your trusted Apple devices"
	if kind == "sms" {
		where = "SMS"
	}
	ui.Step("A 2FA code was sent to %s.", where)
	return ui.Ask("6-digit code: ")
}

func nonInteractiveTwoFA(string) (string, error) {
	return "", &gsa.Error{Msg: "Apple asked for a 2FA code during the automatic token refresh (the anisette " +
		"machine identity likely changed) - run `ap login` once interactively to re-establish trust"}
}

// mintPET mints a fresh GSA PET for escrowproxy Basic auth and returns it with its
// expiry. Silent on an already-trusted device.
func mintPET(dev *device.Device, anis anisette.Provider, username, password string) (string, time.Time, error) {
	spd, err := gsa.AuthenticateWith2FA(gsa.NewClient(dev, anis), username, password, twoFAPrompt)
	if err != nil {
		return "", time.Time{}, err
	}
	_, pet, expiryMS, err := gsa.ExtractPET(spd)
	if err != nil {
		return "", time.Time{}, err
	}
	return pet, time.UnixMilli(expiryMS), nil
}

func describeBottle(b octagon.Bottle) string {
	cm := plistx.Dict(b.Meta["ClientMetadata"])
	var name string
	for _, k := range []string{"device_model", "model", "ProductType", "device_name", "deviceName"} {
		if name = plistx.Str(cm[k]); name != "" {
			break
		}
	}
	if name == "" {
		name = "unknown device"
	}
	return fmt.Sprintf("%s (%s)", name, plistx.Str(b.Meta["serial"]))
}

func selectBottle(bottles []octagon.Bottle) *octagon.Bottle {
	if len(bottles) == 1 {
		ui.Step("Using the only escrow bottle: %s", describeBottle(bottles[0]))
		return &bottles[0]
	}
	ui.Step("Multiple escrow bottles found. Pick the device you want to use:\n")
	for i, b := range bottles {
		ui.Step("  %d)  %s", i+1, describeBottle(b))
	}
	ui.Step("")
	for {
		raw, err := ui.Ask(fmt.Sprintf("Select 1-%d (blank to abort): ", len(bottles)))
		if err != nil || raw == "" {
			return nil
		}
		var n int
		if _, err := fmt.Sscanf(raw, "%d", &n); err == nil && n >= 1 && n <= len(bottles) {
			return &bottles[n-1]
		}
		ui.Err("invalid selection")
	}
}

// refreshWebservices fetches account settings and caches the webservices URL map +
// cloudKitToken. Returns the endpoint count.
func refreshWebservices(s *session.Session, dev *device.Device, anis anisette.Provider) (int, error) {
	mme := s.EnsureMME()
	status, data, err := icloud.FetchAccountSettings(mme.DSID, mme.MmeAuthToken, dev, anis)
	if err != nil {
		return 0, err
	}
	if status == 401 || plistx.Str(data["ErrorID"]) == "UNAUTHORIZED" {
		desc := plistx.Str(data["description"])
		if desc == "" {
			desc = "unauthorized"
		}
		return 0, &icloud.Error{Msg: fmt.Sprintf("iCloud credentials expired (%s) - run `ap login` to re-authenticate", desc), HTTPStatus: status}
	}
	if st, ok := data["status"]; ok && plistx.Int(st) != 0 {
		return 0, &icloud.Error{Msg: fmt.Sprintf("iCloud rejected the token: %s", plistx.Str(data["status-message"]))}
	}
	ws := icloud.ExtractWebservices(data)
	logx.Debugf("icloud", "account settings: HTTP %d keys=%v dataclasses=%v services=%v", status,
		logx.Keys(data), logx.Keys(plistx.Dict(data["com.apple.mobileme"])), logx.Keys(ws))
	if len(ws) == 0 {
		return 0, nil
	}
	s.Webservices = ws
	for k, v := range plistx.Dict(data["tokens"]) {
		if sv := plistx.Str(v); sv != "" {
			mme.Tokens[k] = sv
		}
	}
	return len(ws), nil
}

// mintTokens does the SRP login, then exchanges the fresh PET for a new mmeAuthToken,
// updating the session in place. Preserves an already-cached cloudKitUserId.
func mintTokens(s *session.Session, username, password string, dev *device.Device, anis anisette.Provider, twofa gsa.TwoFactorFunc) error {
	client := gsa.NewClient(dev, anis)
	spd, err := gsa.AuthenticateWith2FA(client, username, password, twofa)
	if err != nil {
		return err
	}
	dsid, pet, petExpiry, err := gsa.ExtractPET(spd)
	if err != nil {
		return err
	}
	logx.Debugf("login", "GSA sign-in ok: dsid=%s pet-expiry=%s app-tokens=%v", dsid,
		time.UnixMilli(petExpiry).Format(time.RFC3339), logx.Keys(plistx.Dict(spd["t"])))
	s.Username = username
	s.DSID = dsid
	s.DSIDNumeric = plistx.Str(spd["DsPrsId"])
	s.PET = pet
	s.PETExpiry = petExpiry
	s.LoggedInAt = time.Now().Unix()
	s.GsIdms = plistx.Str(spd["GsIdmsToken"])
	s.AppTokens = map[string]session.AppToken{}
	for name, e := range plistx.Dict(spd["t"]) {
		d := plistx.Dict(e)
		if d == nil {
			continue
		}
		s.AppTokens[name] = session.AppToken{Token: plistx.Str(d["token"]), Expiry: plistx.Int(d["expiry"]), Duration: plistx.Int(d["duration"])}
	}
	mmeDSID, mmeToken, serviceData, _, err := icloud.LoginMobileMe(username, pet, dsid, dev.LocalUserUUID, dev, anis)
	if err != nil {
		return err
	}
	mme := s.EnsureMME()
	mme.DSID = mmeDSID
	mme.MmeAuthToken = mmeToken
	mme.Tokens = map[string]string{}
	for k, v := range plistx.Dict(serviceData["tokens"]) {
		mme.Tokens[k] = plistx.Str(v)
	}
	mme.MintedAt = time.Now().Unix()
	logx.Debugf("login", "mobileme login ok: mme-dsid=%s mmeAuthToken=%v service tokens=%v", mmeDSID, mmeToken != "", logx.Keys(mme.Tokens))
	return nil
}

// ensureFreshTokens re-mints the cloudKitToken from the mmeAuthToken; if that has expired
// too, silently re-authenticates with the saved password.
func ensureFreshTokens(s *session.Session, dev *device.Device, anis anisette.Provider, interactive bool) error {
	_, err := refreshWebservices(s, dev, anis)
	if err == nil {
		return nil
	}
	var ierr *icloud.Error
	if !errors.As(err, &ierr) || s.Password == "" || s.Username == "" {
		return err
	}
	logx.Errorf("sync", err, "account settings refresh failed; re-authenticating with the saved password")
	ui.Step("iCloud token expired - re-authenticating with the saved password...")
	twofa := twoFAPrompt
	if !interactive {
		twofa = nonInteractiveTwoFA
	}
	if err := mintTokens(s, s.Username, s.Password, dev, anis, twofa); err != nil {
		return err
	}
	_, err = refreshWebservices(s, dev, anis)
	return err
}

func cmdLogin(args []string) (int, error) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	username := fs.String("username", "", "Apple ID (prompted if omitted)")
	fs.StringVar(username, "u", "", "Apple ID (short)")
	noSave := fs.Bool("no-save-password", false, "don't store the password for silent token refresh")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	dev, err := device.LoadOrCreate()
	if err != nil {
		return 1, err
	}
	anis := provider()
	if _, err := anis.Headers(); err != nil { // fail fast: downloads/provisions ADI on first use
		return 2, err
	}
	logx.Debugf("login", "device id=%s serial=%s; anisette ready", dev.DeviceID, dev.Serial)
	prior, err := session.Load()
	if err != nil {
		return 1, err
	}
	if prior == nil {
		prior = &session.Session{}
	}
	logx.Debugf("login", "prior session: %s", prior.Summary())
	user := *username
	if user == "" {
		prompt := "Apple ID: "
		if prior.Username != "" {
			prompt = fmt.Sprintf("Apple ID [%s]: ", prior.Username)
		}
		user, _ = ui.Ask(prompt)
		if user == "" {
			user = prior.Username
		}
	}
	if user == "" {
		return 2, errors.New("no Apple ID given")
	}
	password, err := ui.Secret("Password: ")
	if err != nil {
		return 1, err
	}

	// Preserve the Octagon peer identity (and cached cloudKitUserId) across re-logins:
	// keychain trust membership is permanent and tied to that keypair.
	s := &session.Session{}
	if prior.Octagon != nil && prior.Octagon.PeerID != "" {
		s.Octagon = prior.Octagon
	}
	if prior.MME != nil && prior.MME.CloudKitUserID != "" {
		s.EnsureMME().CloudKitUserID = prior.MME.CloudKitUserID
	}
	if prior.WebAuth != nil {
		s.WebAuth = prior.WebAuth
	}
	if !*noSave {
		s.Password = password
	}

	mmeOK := false
	logx.Debugf("login", "signing in as %s", user)
	if err := mintTokens(s, user, password, dev, anis, twoFAPrompt); err != nil {
		logx.Errorf("login", err, "token mint failed")
		var ierr *icloud.Error
		if errors.As(err, &ierr) {
			ui.Warn("could not mint the persistent mmeAuthToken: %v", err)
		} else {
			return 1, fmt.Errorf("sign-in failed: %w", err)
		}
	} else {
		mmeOK = true
	}
	nWS := 0
	if mmeOK {
		if nWS, err = refreshWebservices(s, dev, anis); err != nil {
			ui.Warn("could not fetch iCloud service URLs: %v", err)
		}
	}
	if err := session.Save(s); err != nil {
		return 1, err
	}
	ui.Out("Signed in as %s.", user)
	if !mmeOK || nWS == 0 {
		return 1, errors.New("sign-in succeeded but iCloud service URLs are unavailable - cannot join the keychain")
	}
	rc := joinAndSync(s, dev, anis, user, password)
	// Hide My Email: its web session is a separate auth surface that may need its own 2FA,
	// so handle that during login rather than surprising a later `ap sync`.
	if n := len(fetchAliasesBestEffort(true)); n > 0 {
		ui.Out("Cached %d Hide My Email alias(es).", n)
	}
	return rc, nil
}

func joinAndSync(s *session.Session, dev *device.Device, anis anisette.Provider, username, password string) int {
	if s.IsJoined() {
		ui.Step("Already joined; syncing...")
		client, err := octagon.NewClient(s, dev, anis)
		if err != nil {
			ui.Err("sync failed: %v", err)
			return 1
		}
		_ = session.Save(s)
		n, err := client.SyncAndDecrypt()
		if err != nil {
			ui.Err("sync failed: %v", err)
			return 1
		}
		ui.Out("Synced %d credential(s) into the vault.", n)
		return 0
	}
	escrowHost := s.Webservices["keychainsync"]
	if escrowHost == "" {
		ui.Err("no escrow URL cached (services: %v) - cannot join the keychain", logx.Keys(s.Webservices))
		return 1
	}
	logx.Debugf("join", "escrow host %s; peer identity %v", escrowHost, s.Octagon != nil && s.Octagon.PeerID != "")
	if _, err := octagon.EnsurePeerIdentity(s, dev); err != nil {
		ui.Err("%v", err)
		return 1
	}
	_ = session.Save(s)
	client, err := octagon.NewClient(s, dev, anis)
	if err != nil {
		ui.Err("%v", err)
		return 1
	}
	_ = session.Save(s) // persist the cloudKitUserId resolved by ckAppInit
	ui.Step("Discovering escrow bottles...")
	pet, petExpiry, err := mintPET(dev, anis, username, password)
	if err != nil {
		ui.Err("%v", err)
		return 1
	}
	listPET := pet
	bottles, err := client.ListRecoverableBottles(escrowHost, username, listPET, func(m string) { ui.Warn("%s", m) })
	if err != nil {
		logx.Errorf("join", err, "bottle discovery failed")
		ui.Err("%v", err)
		return 1
	}
	for _, b := range bottles {
		logx.Debugf("join", "bottle %s: %s (meta keys %v)", b.ID, describeBottle(b), logx.Keys(b.Meta))
	}
	if len(bottles) == 0 {
		ui.Err("no recoverable escrow bottle - cannot join via this path")
		return 1
	}
	chosen := selectBottle(bottles)
	if chosen == nil {
		ui.Out("Aborted before selecting a bottle - no escrow attempt spent. You're signed in but NOT joined; run `ap login` again to retry the keychain join.")
		return 0
	}
	logx.Debugf("join", "chosen bottle %s", chosen.ID)
	ui.Out("Joining iCloud Keychain will use the passcode of: %s", describeBottle(*chosen))
	ui.Out("This is IRREVERSIBLE - a wrong passcode spends 1 of ~10 attempts, and the 10th failed attempt destroys the escrow record permanently.")
	if !ui.ConfirmYN("Proceed? (y/N) ") {
		ui.Out("Aborted - no escrow attempt spent. You're signed in but NOT joined; run `ap login` again to retry the keychain join.")
		return 0
	}
	// Re-mint the PET before the irreversible recovery only if the one from the listing
	// could expire during the passcode prompt: every extra GSA sign-in risks Apple's
	// throttling (HTTP 503) at the worst moment.
	if time.Until(petExpiry) < 5*time.Minute {
		if pet, _, err = mintPET(dev, anis, username, password); err != nil {
			ui.Err("sign-in failed: %v", err)
			return 1
		}
	}
	passcode, err := ui.Secret("Device passcode / iCloud Security Code for that device: ")
	if err != nil || passcode == "" {
		ui.Err("empty passcode - aborting before spending an attempt")
		return 1
	}
	if _, err := client.JoinViaEscrow(escrowHost, username, pet, []byte(passcode), chosen, true); err != nil {
		ui.Err("join failed: %v", err)
		return 1
	}
	_ = session.Save(s) // persist the peer identity + the recovered sponsor key
	n, err := client.SyncAndDecrypt()
	if err != nil {
		ui.Err("joined, but sync failed: %v", err)
		return 1
	}
	ui.Out("Joined the keychain. Synced %d credential(s).", n)
	return 0
}

func utcMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

type statusRow struct {
	label string
	value string
}

func statusFields() []statusRow {
	s, err := session.Load()
	if err != nil {
		return []statusRow{{"Status", err.Error()}}
	}
	if s == nil {
		return []statusRow{{"Status", "not signed in - run: ap login"}}
	}
	rows := []statusRow{
		{"Apple ID", s.Username},
		{"DSID", s.DSID},
		{"Signed in", utcMillis(s.LoggedInAt * 1000).Format(time.RFC3339)},
	}
	now := time.Now()
	if t, ok := s.AppTokens[icloudAuthToken]; ok && t.Expiry != 0 {
		exp := utcMillis(t.Expiry)
		state := "valid"
		if !exp.After(now) {
			state = "EXPIRED"
		}
		rows = append(rows, statusRow{"iCloud token", fmt.Sprintf("%s, until %s (~%d days)", state, exp.Format("2006-01-02"), int(exp.Sub(now).Hours()/24))})
	}
	rows = append(rows, statusRow{"App tokens", fmt.Sprint(len(s.AppTokens))})
	if s.MME != nil && s.MME.MmeAuthToken != "" {
		rows = append(rows, statusRow{"mmeAuthToken", fmt.Sprintf("present (dsid %s) - persistent", s.MME.DSID)})
	} else {
		rows = append(rows, statusRow{"mmeAuthToken", "none - run login"})
	}
	if len(s.Webservices) > 0 {
		rows = append(rows, statusRow{"Service URLs", fmt.Sprintf("%d cached", len(s.Webservices))})
	} else {
		rows = append(rows, statusRow{"Service URLs", "none - run login"})
	}
	peer := "not yet joined"
	if s.Octagon != nil && s.Octagon.PeerID != "" {
		peer = s.Octagon.PeerID
	}
	rows = append(rows, statusRow{"Octagon peer", peer})
	if dev, err := device.LoadOrCreate(); err == nil {
		rows = append(rows, statusRow{"Device ID", dev.DeviceID})
	}
	return rows
}

func statusSummary() string {
	s, err := session.Load()
	if err != nil || s == nil {
		return "not signed in - run: ap login"
	}
	joined := "not joined"
	if s.IsJoined() {
		joined = "joined"
	}
	token := ""
	if t, ok := s.AppTokens[icloudAuthToken]; ok && t.Expiry != 0 {
		exp := utcMillis(t.Expiry)
		valid := "valid"
		if !exp.After(time.Now()) {
			valid = "EXPIRED"
		}
		token = fmt.Sprintf("  |  token %s %s", valid, exp.Format("2006-01-02"))
	}
	return fmt.Sprintf("%s  |  dsid %s  |  %s%s", s.Username, s.DSID, joined, token)
}

func matchCred(c vault.Credential, q string) bool {
	return q == "" || strings.Contains(strings.ToLower(c.Domain), q) ||
		strings.Contains(strings.ToLower(c.Title), q) || strings.Contains(strings.ToLower(c.Username), q)
}

func matchAlias(a hme.Alias, q string) bool {
	return q == "" || strings.Contains(strings.ToLower(a.Address), q) || strings.Contains(strings.ToLower(a.Label), q) ||
		strings.Contains(strings.ToLower(a.Note), q) || strings.Contains(strings.ToLower(a.ForwardTo), q)
}

// fetchAliasesBestEffort fetches Hide My Email aliases via the web session. Never fails
// the caller: no saved password skips silently, any other error warns and falls back to
// the cached aliases. On success, refreshes that cache for the native host.
func fetchAliasesBestEffort(interactive bool) []hme.Alias {
	s, err := session.Load()
	if err != nil || s == nil || s.Password == "" {
		return nil
	}
	cached := func() []hme.Alias {
		a, _ := hme.LoadAliases()
		return a
	}
	sess, account, err := ensureWebSession(s, interactive)
	if err != nil {
		logx.Errorf("hme", err, "web session unavailable")
		ui.Warn("Hide My Email unavailable: %v", err)
		return cached()
	}
	_ = session.Save(s)
	base := webauth.ExtractWebservices(account)["premiummailsettings"]
	if base == "" {
		return cached()
	}
	aliases, err := hme.NewClient(base, sess.HTTP).List()
	if err != nil {
		logx.Errorf("hme", err, "alias list failed")
		ui.Warn("Hide My Email unavailable: %v", err)
		return cached()
	}
	logx.Debugf("hme", "fetched %d alias(es)", len(aliases))
	_ = hme.SaveAliases(aliases)
	return aliases
}

// ensureWebSession reaches a valid idmsa web session, reusing a saved trust token when
// possible; otherwise signs in with the saved password and prompts for 2FA once.
func ensureWebSession(s *session.Session, interactive bool) (*webauth.Session, map[string]any, error) {
	if s.WebAuth == nil {
		s.WebAuth = &session.WebAuth{}
	}
	wa := s.WebAuth
	if wa.FrameTag == "" {
		wa.FrameTag = "auth-" + strings.ToLower(device.NewUUID())
	}
	sess := webauth.NewSession(wa.FrameTag, wa.SessionData, wa.Cookies)
	var account map[string]any
	if sess.SessionData["session_token"] != "" {
		if a, err := sess.AccountLogin(); err == nil && !webauth.HSAChallengeRequired(a) {
			account = a
		}
	}
	if account == nil {
		if s.Username == "" || s.Password == "" {
			return nil, nil, &webauth.Error{Msg: "no saved Apple ID password for the web session - run `ap login` without --no-save-password"}
		}
		if err := sess.Signin(s.Username, s.Password, sess.SessionData["trust_token"]); err != nil {
			return nil, nil, err
		}
		if sess.NeedsTwoFA {
			if !interactive {
				return nil, nil, &webauth.Error{Msg: "Apple asked for a 2FA code for the web session - run `ap show` from a terminal once to establish trust"}
			}
			if err := sess.RequestPushNotification(); err != nil { // the 409 no longer auto-sends this
				return nil, nil, err
			}
			code, err := twoFAPrompt("trusted")
			if err != nil {
				return nil, nil, err
			}
			if err := sess.Submit2FA(code); err != nil {
				return nil, nil, err
			}
		}
		a, err := sess.AccountLogin()
		if err != nil {
			return nil, nil, err
		}
		if webauth.HSAChallengeRequired(a) {
			return nil, nil, &webauth.Error{Msg: "2FA did not clear the web-session challenge"}
		}
		account = a
	}
	s.WebAuth = sess.Export()
	return sess, account, nil
}

func totpSuffix(c vault.Credential) string {
	code := totp.Generate(c.TOTP)
	if code == nil {
		return ""
	}
	left := code.Expires - time.Now().Unix()
	if left < 0 {
		left = 0
	}
	return fmt.Sprintf("  %s (%ds)", code.Code, left)
}

func cmdShow(args []string) (int, error) {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	showPasswords := fs.Bool("show-passwords", false, "reveal passwords in plain output")
	fs.BoolVar(showPasswords, "s", false, "reveal passwords (short)")
	plain := fs.Bool("plain", false, "print plain text instead of the interactive TUI")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	query := strings.ToLower(strings.TrimSpace(strings.Join(fs.Args(), " ")))
	store, err := vault.LoadVault()
	if err != nil {
		return 1, fmt.Errorf("could not open the vault: %w", err)
	}
	useTUI := !*plain && query == "" && !*showPasswords && ui.IsTerminal()
	if useTUI {
		if err := runTUI(store); err != nil {
			ui.Warn("TUI unavailable (%v); showing plain output", err)
		} else {
			return 0, nil
		}
	}
	return showPlain(store, query, *showPasswords)
}

func showPlain(store *vault.Store, query string, showPasswords bool) (int, error) {
	for _, r := range statusFields() {
		ui.Step("%-14s%s", r.label, r.value)
	}
	var creds []vault.Credential
	for _, c := range store.All() {
		if matchCred(c, query) {
			creds = append(creds, c)
		}
	}
	var aliases []hme.Alias
	for _, a := range fetchAliasesBestEffort(ui.StdinIsTerminal()) {
		if matchAlias(a, query) {
			aliases = append(aliases, a)
		}
	}
	if query != "" && len(creds) == 0 && len(aliases) == 0 {
		return 1, fmt.Errorf("no credentials or aliases match %q", query)
	}
	if len(creds) == 0 && len(aliases) == 0 {
		ui.Step("vault is empty - run: ap login")
		return 0, nil
	}
	if len(creds) > 0 {
		sort.SliceStable(creds, func(i, j int) bool {
			a, b := creds[i], creds[j]
			if strings.ToLower(a.Title) != strings.ToLower(b.Title) {
				return strings.ToLower(a.Title) < strings.ToLower(b.Title)
			}
			return strings.ToLower(a.Username) < strings.ToLower(b.Username)
		})
		domW, userW := 0, 0
		for _, c := range creds {
			domW = max(domW, len(c.Domain))
			userW = max(userW, len(c.Username))
		}
		domW, userW = min(domW, 40), min(userW, 40)
		for _, c := range creds {
			pw := "******"
			if showPasswords {
				pw = c.Password
			}
			ui.Out("%-*s  %-*s  %s%s", domW, c.Domain, userW, c.Username, pw, totpSuffix(c))
		}
		ui.Step("%d credential(s).", len(creds))
	}
	if len(aliases) > 0 {
		sort.SliceStable(aliases, func(i, j int) bool {
			return strings.ToLower(aliases[i].Label) < strings.ToLower(aliases[j].Label)
		})
		labelW := 0
		for _, a := range aliases {
			labelW = max(labelW, len(a.Label))
		}
		labelW = min(labelW, 32)
		ui.Step("")
		ui.Step("Hide My Email:")
		for _, a := range aliases {
			state := ""
			if !a.IsActive {
				state = "  (inactive)"
			}
			ui.Out("%-*s  %s%s", labelW, a.Label, a.Address, state)
		}
		ui.Step("%d alias(es).", len(aliases))
	}
	return 0, nil
}

func lockSync() (*os.File, bool, error) {
	f, err := os.OpenFile(paths.SyncLockFile(), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, false, nil
	}
	return f, true, nil
}

func cmdSync(args []string) (int, error) {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	lock, ok, err := lockSync()
	if err != nil {
		return 1, err
	}
	if !ok {
		ui.Err("another sync is already running")
		return 0, nil
	}
	defer func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
	}()
	s, err := session.Load()
	if err != nil {
		return 1, err
	}
	if s == nil {
		return 1, errors.New("not signed in - run: ap login")
	}
	if s.Octagon == nil || s.Octagon.PeerID == "" {
		return 1, errors.New("not joined to the keychain - run: ap login")
	}
	dev, err := device.LoadOrCreate()
	if err != nil {
		return 1, err
	}
	anis := provider()
	// The cached cloudKitToken is short-lived; re-mint it from the mmeAuthToken before
	// every sync. If that has expired too, re-authenticate with the saved password.
	if err := ensureFreshTokens(s, dev, anis, ui.StdinIsTerminal()); err != nil {
		return 1, fmt.Errorf("could not refresh the iCloud token: %w", err)
	}
	_ = session.Save(s)
	client, err := octagon.NewClient(s, dev, anis)
	if err != nil {
		return 1, fmt.Errorf("sync failed: %w", err)
	}
	_ = session.Save(s)
	n, err := client.SyncAndDecrypt()
	if err != nil {
		var ckErr *cloudkit.Error
		if errors.As(err, &ckErr) && ckErr.HTTPStatus == 401 {
			return 1, fmt.Errorf("sync failed: CloudKit rejected the token (%w) - run `ap login` if this persists", err)
		}
		return 1, fmt.Errorf("sync failed: %w", err)
	}
	ui.Out("Synced %d credential(s) into the vault.", n)
	// Best-effort, never interactive: refresh the Hide My Email cache only while the web
	// session's trust is still valid, otherwise keep the cache.
	if na := len(fetchAliasesBestEffort(false)); na > 0 {
		ui.Out("Cached %d Hide My Email alias(es).", na)
	}
	return 0, nil
}

func cmdLogout(args []string) (int, error) {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	wipe := fs.Bool("wipe-device", false, "also remove the device identity")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	if err := session.Clear(); err != nil {
		return 1, err
	}
	ui.Out("Session cleared. Device identity kept (use --wipe-device to remove it).")
	if *wipe {
		if err := os.Remove(paths.RemoteAnisetteFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 1, err
		}
		if err := device.Delete(); err != nil {
			return 1, err
		}
		ui.Out("Device identity wiped.")
	}
	return 0, nil
}

func cmdInstallHost(args []string) (int, error) {
	fs := flag.NewFlagSet("install-host", flag.ContinueOnError)
	hostBin := fs.String("host-binary", "", "path to ap-host (default: next to ap, else on PATH)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ap install-host [--host-binary PATH] [CHROME_EXTENSION_ID]\n\n"+
			"Registers the native-messaging host with the browsers found on this machine.\n"+
			"For Chromium-family browsers, load %s unpacked first and pass the extension id it shows.\n"+
			"Firefox is keyed by the fixed add-on id, so it needs no argument.\n", extensionDirHint())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	extID := ""
	if fs.NArg() > 0 {
		extID = fs.Arg(0)
	}
	bin := *hostBin
	if bin == "" {
		var err error
		if bin, err = hostinstall.HostBinary(); err != nil {
			return 1, err
		}
	}
	written, err := hostinstall.Install(bin, extID, func(m string) { ui.Step("%s", m) })
	for _, p := range written {
		ui.Out("installed: %s", p)
	}
	if err != nil {
		return 1, err
	}
	ui.Out("Done. Reload the extension; the popup should connect to the host.")
	return 0, nil
}

func extensionDirHint() string {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "..", "share", "ap", "extension")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return filepath.Clean(cand)
		}
	}
	return "the extension/ folder"
}
