# Home Manager module for ap: installs the CLI, refreshes the vault on a timer, and
# registers the browser extension's native-messaging host with the browsers you enable.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.ap;
  inherit (lib) mkEnableOption mkOption mkIf types optionalAttrs;

  hostName = "io.github.hpidcock.ap";
  geckoId = "ap@hpidcock.github.io";
  hostBinary = "${cfg.package}/bin/ap-host";

  chromiumManifest = builtins.toJSON {
    name = hostName;
    description = "Apple Passwords native messaging host (ap)";
    path = hostBinary;
    type = "stdio";
    allowed_origins = [ "chrome-extension://${cfg.browsers.chromeExtensionId}/" ];
  };
  firefoxManifest = builtins.toJSON {
    name = hostName;
    description = "Apple Passwords native messaging host (ap)";
    path = hostBinary;
    type = "stdio";
    allowed_extensions = [ geckoId ];
  };

  chromiumDirs = {
    chromium = ".config/chromium/NativeMessagingHosts";
    chrome = ".config/google-chrome/NativeMessagingHosts";
    brave = ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts";
    helium = ".config/net.imput.helium/NativeMessagingHosts";
    vivaldi = ".config/vivaldi/NativeMessagingHosts";
  };
  firefoxDirs = {
    firefox = ".mozilla/native-messaging-hosts";
    librewolf = ".librewolf/native-messaging-hosts";
  };

  chromiumFiles = lib.mapAttrs' (name: dir:
    lib.nameValuePair "${dir}/${hostName}.json" { text = chromiumManifest; })
    (lib.filterAttrs (name: _: cfg.browsers.${name} && cfg.browsers.chromeExtensionId != null) chromiumDirs);
  firefoxFiles = lib.mapAttrs' (name: dir:
    lib.nameValuePair "${dir}/${hostName}.json" { text = firefoxManifest; })
    (lib.filterAttrs (name: _: cfg.browsers.${name}) firefoxDirs);
in
{
  options.services.ap = {
    enable = mkEnableOption "ap, the unofficial iCloud Keychain client";

    package = mkOption {
      type = types.package;
      description = "The ap package to use.";
    };

    sync = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Refresh the vault periodically with a systemd user timer (only once a session exists).";
      };
      interval = mkOption {
        type = types.str;
        default = "6h";
        description = "How often to run `ap sync` (a systemd time span).";
      };
    };

    browsers = {
      chromeExtensionId = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "abcdefghijklmnopabcdefghijklmnop";
        description = ''
          The extension id a Chromium-family browser assigned to the unpacked extension
          (`''${package}/share/ap/extension`). Required to register the native host with
          Chromium, Chrome, Brave, Helium or Vivaldi.
        '';
      };
      chromium = mkOption { type = types.bool; default = true; description = "Register the native host for Chromium."; };
      chrome = mkOption { type = types.bool; default = false; description = "Register the native host for Google Chrome."; };
      brave = mkOption { type = types.bool; default = false; description = "Register the native host for Brave."; };
      helium = mkOption { type = types.bool; default = false; description = "Register the native host for Helium."; };
      vivaldi = mkOption { type = types.bool; default = false; description = "Register the native host for Vivaldi."; };
      firefox = mkOption { type = types.bool; default = true; description = "Register the native host for Firefox."; };
      librewolf = mkOption { type = types.bool; default = false; description = "Register the native host for LibreWolf."; };
    };
  };

  config = mkIf cfg.enable {
    home.packages = [ cfg.package ];

    home.file = chromiumFiles // firefoxFiles;

    systemd.user.services.ap-sync = mkIf cfg.sync.enable {
      Unit = {
        Description = "ap - refresh the iCloud Keychain vault";
        After = [ "network-online.target" ];
        # Only once `ap login` has created a session.
        ConditionPathExists = "%E/ap/session.enc";
      };
      Service = {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/ap sync";
      };
    };

    systemd.user.timers.ap-sync = mkIf cfg.sync.enable {
      Unit.Description = "ap - periodic keychain refresh";
      Timer = {
        OnBootSec = "5m";
        OnUnitActiveSec = cfg.sync.interval;
        Persistent = true;
      };
      Install.WantedBy = [ "timers.target" ];
    };
  };
}
