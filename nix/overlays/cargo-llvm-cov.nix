final: prev: {
  cargo-llvm-cov = prev.rustPlatform.buildRustPackage rec {
    pname = "cargo-llvm-cov";
    version = "0.5.31";
    buildInputs = [ ];

    src = final.fetchCrate {
      inherit pname version;
      sha256 = "sha256-HjnP9H1t660PJ5eXzgAhrdDEgqdzzb+9Dbk5RGUPjaQ=";
    };
    doCheck = false;
    cargoHash = "sha256-p6zpRRNX4g+jESNSwouWMjZlFhTBFJhe7LirYtFrZ1g=";
  };
}
