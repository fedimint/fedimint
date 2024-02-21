final: prev: {
  esplora-electrs = prev.callPackage ../pkgs/esplora-electrs.nix {
    inherit (prev.darwin.apple_sdk.frameworks) Security;
  };
}
