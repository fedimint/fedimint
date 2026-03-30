# pin wasm-bindgen to version we expect
final: prev: {
  wasm-bindgen-cli = final.rustPlatform.buildRustPackage rec {
    pname = "wasm-bindgen-cli";
    version = "0.2.104";
    hash = "";
    cargoHash = "";

    src = final.fetchCrate { inherit pname version hash; };

    nativeBuildInputs = [ final.pkg-config ];

    buildInputs = [
      final.openssl
    ]
    ++ final.lib.optionals final.stdenv.isDarwin [
      final.curl
    ];

    nativeCheckInputs = [ final.nodejs ];

    # tests require it to be ran in the wasm-bindgen monorepo
    doCheck = false;
  };
}
