# ap - iCloud Keychain for Linux, in Go

**Unofficial** client for iCloud Keychain. Sign in with your Apple ID and `ap` registers this
computer as one of your Apple devices, joins your keychain, and downloads your passwords into
a private, encrypted vault on your machine. A browser extension fills them in for you, like the
Passwords app on a Mac or iPhone. Your Hide My Email addresses show up too. `ap` only ever
*reads*: nothing in your Apple account is changed.

This project is a Go rewrite of two upstream projects, combined into one binary:

- [Sank6/iCloud-Keychain-for-Linux](https://github.com/Sank6/iCloud-Keychain-for-Linux) (`icp`,
  Python) - the GrandSlam sign-in, Octagon trust join, CloudKit transport, keychain decryption,
  native-messaging host, and the browser extension (kept as-is under `extension/`).
- [Dadoum/anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) (D) and the
  [Dadoum/Provision](https://github.com/Dadoum/Provision) library it is built on - the code that
  produces the machine data Apple's sign-in requires. `ap` speaks the anisette-v3 protocol to
  such a server (the default), and also carries a Go port of the Android ADI side so it can
  generate the data in process (`--anisette local`), which Apple has blocked since 2026-10-15.

Like the upstream project this is a reverse-engineering effort, **not affiliated with Apple**,
and it is untested with Advanced Data Protection enabled.

## How it fits together

```
ap login / ap sync ──► gsa.apple.com, setup.icloud.com, gateway.icloud.com (CloudKit)
        │
        │ every request carries X-Apple-I-MD* machine data, fetched from an
        └─► anisette-v3 server (default) or generated in-process by Apple's CoreADI

~/.config/ap/vault.enc  ◄──  ap-host (native-messaging)  ◄──  browser extension
```

The machine data is the part Apple keeps moving. Since October 2026 Apple checks the
client-info string of every request against the platform of the library that produced the
machine data, and blocks the Android library outright, so by default `ap` uses an anisette-v3
server instead: on first use it generates a random machine identifier, runs Apple's
provisioning handshake once with the server answering the cryptographic challenge, stores the
identifier and the provisioning blob Apple issued in `~/.config/ap/anisette-remote.json`, and
from then on asks the server to turn them into a one-time password before each request. The
server also tells `ap` which client info its machine data is valid for. It never sees your
Apple ID, password or any token. The default server is the one isideload and iloader use
(`https://ani.jkcoxson.com`); `--anisette URL` picks another, such as your own
[anisette-v3-server](https://github.com/Dadoum/anisette-v3-server), and the choice is
remembered for later runs.

`--anisette local` keeps everything in process instead: `ap` downloads `libCoreADI.so` /
`libstoreservicescore.so` from Apple's public Apple Music for Android package into
`~/.config/ap/anisette/lib`, loads them with a small ELF loader
(`internal/anisette/local/androidlib`), provisions once and generates the headers itself. It is
kept for when Apple accepts Android client info again.

## Install

### Nix flake

```
nix run github:hpidcock/ap -- --help
nix profile install github:hpidcock/ap
```

### Home Manager

The flake exports a Home Manager module that installs the CLI, refreshes the vault on a timer,
and registers the browser extension's native messaging host:

```nix
{
  inputs.ap.url = "github:hpidcock/ap";

  # in your home-manager configuration:
  imports = [ inputs.ap.homeManagerModules.default ];

  services.ap = {
    enable = true;
    sync.interval = "6h";            # systemd user timer running `ap sync`
    browsers = {
      firefox = true;                # ~/.mozilla/native-messaging-hosts
      chromium = true;               # needs the extension id below
      chromeExtensionId = "abcdefghijklmnopabcdefghijklmnop";
    };
  };
}
```

The extension folder to load unpacked is `${pkgs.ap}/share/ap/extension`. The sync timer only
fires once a session exists (after `ap login`).

### From source

```
go build ./cmd/ap ./cmd/ap-host
```

cgo and a C compiler are required for the embedded anisette server.

## Sign in

```
ap login
```

The first run downloads Apple's ADI libraries (about 140 MB) and provisions this machine with
Apple; after that, sign-in walks you through the login: your Apple ID, password, and the 2FA code Apple sends to your
other devices. `ap` then asks for a **device passcode or iCloud Security Code** so it can join
your keychain.

- You're only asked for your password and 2FA code **once**; the device stays trusted.
- The passcode step is **important and can't be undone**: entering the wrong passcode too many
  times (about 10) permanently locks your keychain recovery. One correct entry is perfectly safe.
  `ap` shows which device each escrow record belongs to and asks for an explicit confirmation
  before spending an attempt.
- Your 2FA code and passcode are used immediately and **never saved**. Your password and tokens
  are kept encrypted on your computer (master key in the login keyring via Secret Service, or a
  0600 key file if no keyring is available) so `ap` can stay signed in. Pass
  `--no-save-password` to skip storing the password.

## Browse your passwords

```
ap show              # full-screen browser: type to filter, Enter reveals, Esc clears/quits
ap show github       # plain-text search
ap show --plain -s   # plain text with passwords revealed
```

Verification codes set up in the Passwords app are shown next to the login with a live countdown.

## Browser extension

The `extension/` folder (also installed to `share/ap/extension`) works in Chromium-based
browsers and Firefox.

**Chrome, Chromium, Brave, Helium:** open the extensions page, enable Developer mode, *Load
unpacked* the extension folder, copy the extension id, then run

```
ap install-host <EXTENSION_ID>
```

**Firefox:** load `extension/manifest.json` as a temporary add-on from
`about:debugging#/runtime/this-firefox`, then run `ap install-host`.

`ap install-host` writes the native-messaging manifests pointing at `ap-host`; with Home Manager
the module writes them for you. On a sign-in page, click the username or password box: an
**iCloud Passwords** dropdown appears with matching logins. Two-factor code boxes get the current
code instead.

## Keeping your passwords up to date

Your passwords are a snapshot. `ap-host` kicks off a background `ap sync` when the vault is
older than 6 hours (`AP_SYNC_MAX_AGE` seconds, 0 to disable) and the Home Manager timer does the
same. To refresh right now:

```
ap sync
```

## All commands

```
login         sign in, join your iCloud Keychain, and download your passwords
show          browse and search your passwords and Hide My Email addresses
sync          refresh your passwords now
logout        sign out (use --wipe-device to also forget this device)
install-host  register the browser extension's native-messaging host
```

Environment: `XDG_CONFIG_HOME` (state lives in `$XDG_CONFIG_HOME/ap`), `AP_NO_KEYRING=1` (always use the
key file), `AP_INSECURE_TLS=1` (disable TLS verification, debugging only).

## Troubleshooting

When something fails, re-run with `--debug` (anywhere on the command line, or `AP_DEBUG=1`) and `ap`
prints every step and every exchange with Apple to stderr: the GrandSlam status codes, which
delegates and service URLs `setup.icloud.com` returned, each CloudKit and escrowproxy call with its
result code, and how many keychain records were fetched, unwrapped and decrypted, including why any
were skipped. `--trace` (`AP_DEBUG=2`) adds request and response bodies. `--log-file PATH`
(`AP_LOG_FILE`) appends the full trace to a private file whether or not `--debug` is set, which is
the way to capture the background sync or the native-messaging host (`ap-host` reads the same
variables; set them in the Home Manager module or the host's environment).

Everything that could authenticate as you is redacted before it is written: Basic auth, tokens,
cookies, 2FA codes, anisette machine data, and passwords, proofs and PETs inside bodies. The log
still names your Apple ID, device IDs and the devices in your escrow bottles, so treat it as private.

Apple error codes `ap` has run into: `-80045` "This action cannot be completed at this time" means
the client info and the anisette machine data disagree about the platform (switch anisette
servers, or run `ap logout --wipe-device` to provision afresh), `hsc=409` means a 2FA code is
already on its way to your trusted devices, and HTTP 503 from `gsa.apple.com` is Apple's edge
refusing the client info outright (Android since 2026-10-15, Xcode since September 2026) or
a reused keep-alive connection; `ap` opens a fresh connection per request and retries 429/503.

## Differences from the upstream projects

- One Go binary, no Python environment and no Docker: the anisette machine data is generated
  in-process instead of by a separate server.
- TLS is verified. The upstream Python client disabled certificate checks; `ap` instead embeds
  Apple's root CA (which gsa.apple.com chains to) alongside the system roots.
- The native host is `ap-host`; the extension's host name is `io.github.hpidcock.ap`.
- The vault, session and alias cache keep the upstream on-disk formats (libsodium secret box,
  JSON inside), but live under `~/.config/ap`.

See `RESEARCH.md` in the upstream repository for the protocol notes this port follows.

## Development

```
go test ./...                                   # offline unit tests
AP_ANISETTE_LIBDIR=~/.config/ap/anisette/lib \
  go test -tags live ./internal/anisette/local  # live provisioning test against Apple
nix build                                       # flake package
```

## Credits and licenses

The GrandSlam sign-in flow follows [JJTech's reference](https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452).
The keychain decryption, Octagon trust join and CloudKit transport follow
[OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush), cross-checked against
[Apple's open-source Security code](https://github.com/apple-oss-distributions/Security). Hide My
Email is ported from [dedoussis's browser extension](https://github.com/dedoussis/icloud-hide-my-email-browser-extension).
All of this was first assembled by [Sank6/iCloud-Keychain-for-Linux](https://github.com/Sank6/iCloud-Keychain-for-Linux),
whose MIT license is reproduced in [LICENSE.md](LICENSE.md) and covers this project.

The machine-data generator under `internal/anisette/local` is a port of the ADI side of
[Dadoum/anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) and of the loader /
ADI wrapper from [Dadoum/Provision](https://github.com/Dadoum/Provision), which is licensed under
the GNU Library General Public License v2 (see `internal/anisette/local/COPYING-LGPLv2`); that
subtree is available under those terms as well. Apple's CoreADI libraries are downloaded at
runtime from Apple and are not redistributed here.
