# pin wasm-bindgen to version we expect
final: prev: {
  wasm-bindgen-cli = final.rustPlatform.buildRustPackage rec {
    pname = "wasm-bindgen-cli";
    version = "0.2.92";
    hash = "sha256-1VwY8vQy7soKEgbki4LD+v259751kKxSxmo/gqE6yV0=";
    cargoHash = "sha256-aACJ+lYNEU8FFBs158G1/JG8sc6Rq080PeKCMnwdpH0=";

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
