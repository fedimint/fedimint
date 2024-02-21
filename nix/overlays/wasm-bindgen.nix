# pin wasm-bindgen to version we expect
final: prev: {
  wasm-bindgen-cli = final.rustPlatform.buildRustPackage rec {
    pname = "wasm-bindgen-cli";
    version = "0.2.89";
    hash = "sha256-IPxP68xtNSpwJjV2yNMeepAS0anzGl02hYlSTvPocz8=";
    cargoHash = "sha256-pBeQaG6i65uJrJptZQLuIaCb/WCQMhba1Z1OhYqA8Zc=";

    src = final.fetchCrate {
      inherit pname version hash;
    };

    nativeBuildInputs = [ final.pkg-config ];

    buildInputs = [ final.openssl ] ++ final.lib.optionals final.stdenv.isDarwin [
      final.curl
      final.darwin.apple_sdk.frameworks.Security
    ];

    nativeCheckInputs = [ final.nodejs ];

    # tests require it to be ran in the wasm-bindgen monorepo
    doCheck = false;
  };
}
