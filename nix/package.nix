{ lib, buildGoModule, go_1_27 ? null, go }:

(buildGoModule.override { go = if go_1_27 != null then go_1_27 else go; }) {
  pname = "ap";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let base = baseNameOf path;
      in !(lib.hasPrefix "result" base) && base != ".direnv" && base != ".git" && !(lib.hasSuffix ".apk" base);
  };

  vendorHash = "sha256-lKVYoR3Oz7KeG2TawUWBoqlNiN86m3bQVb0Y7W1Db4s=";

  subPackages = [ "cmd/ap" "cmd/ap-host" ];

  # The anisette server loads Apple's Android ADI libraries through a small cgo loader.
  env.CGO_ENABLED = "1";

  ldflags = [ "-s" "-w" ];

  postInstall = ''
    mkdir -p $out/share/ap
    cp -r extension $out/share/ap/extension
  '';

  meta = with lib; {
    description = "Unofficial iCloud Keychain client for Linux with an embedded anisette server";
    homepage = "https://github.com/hpidcock/ap";
    license = licenses.mit;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "ap";
  };
}
