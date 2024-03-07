final: prev: {
  cargo-hongfuzz = prev.callPackage ../pkgs/cargo-honggfuzz.nix {
    inherit (prev.darwin.apple_sdk.frameworks) Security;
  };
}
