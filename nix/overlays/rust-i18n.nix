final: prev: {
  rust-i18n-cli = prev.callPackage ../pkgs/rust-i18n.nix {
    inherit (prev.darwin.apple_sdk.frameworks) Security;
  };
}
