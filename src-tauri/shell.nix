let
  # Bring in rust-overlay for rust-bin
  rustOverlay = import (
    builtins.fetchTarball {
      url = "https://github.com/oxalica/rust-overlay/archive/master.tar.gz";
    }
  );

  pkgs = import <nixpkgs> {
    overlays = [ rustOverlay ];
  };

  rustNightly = pkgs.rust-bin.nightly.latest.default;
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    pkg-config
    gobject-introspection
    nodejs
    cargo-tauri
    rustNightly
    rustup
  ];

  buildInputs = with pkgs; [
    at-spi2-atk
    atkmm
    cairo
    gdk-pixbuf
    glib
    gtk3
    harfbuzz
    librsvg
    libsoup_3
    pango
    webkitgtk_4_1
    openssl
  ];

  shellHook = ''
    echo "Using Rust nightly: $(rustc --version)"
  '';
}
