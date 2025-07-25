# pin wasm-bindgen to version we expect
final: prev: {
  wasm-bindgen-cli = final.rustPlatform.buildRustPackage rec {
    pname = "wasm-bindgen-cli";
    version = "0.2.100";
    hash = "sha256-3RJzK7mkYFrs7C/WkhW9Rr4LdP5ofb2FdYGz1P7Uxog=";
    cargoHash = "sha256-qsO12332HSjWCVKtf1cUePWWb9IdYUmT+8OPj/XP2WE=";

    src = final.fetchCrate { inherit pname version hash; };

    nativeBuildInputs = [ final.pkg-config ];

    buildInputs = [
      final.openssl
    ]
    ++ final.lib.optionals final.stdenv.isDarwin [
      final.curl
      final.darwin.apple_sdk.frameworks.Security
    ];

    nativeCheckInputs = [ final.nodejs ];

    # tests require it to be ran in the wasm-bindgen monorepo
    doCheck = false;
  };
}
