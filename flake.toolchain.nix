{ pkgs, lib, system, stdenv, fenix, android-nixpkgs }:
let
  isArch64Darwin = stdenv.isAarch64 || stdenv.isDarwin;

  # Env vars we need for wasm32 cross compilation
  wasm32CrossEnvVars = ''
    export CC_wasm32_unknown_unknown="${pkgs.llvmPackages_14.clang-unwrapped}/bin/clang-14"
    export CFLAGS_wasm32_unknown_unknown="-I ${pkgs.llvmPackages_14.libclang.lib}/lib/clang/14.0.6/include/ -Wno-macro-redefined"
  '' + (if isArch64Darwin then
    ''
      export AR_wasm32_unknown_unknown="${pkgs.llvmPackages_14.llvm}/bin/llvm-ar"
    '' else
    ''
          '');

  # NDK we use for android cross compilation
  androidSdk =
    android-nixpkgs.sdk."${system}" (sdkPkgs: with sdkPkgs; [
      cmdline-tools-latest
      build-tools-32-0-0
      platform-tools
      platforms-android-31
      emulator
      ndk-bundle
    ]);

  # The following hack makes fedimint compile on android:
  #
  # From https://github.com/rust-mobile/cargo-apk/commit/4956b87f56f2854e2b3452b83b65b00224757d41
  # > Rust still searches for libgcc even though [85806] replaces internal use
  # > with libunwind, especially now that the Android NDK (since r23-beta3)
  # > doesn't ship with any of gcc anymore.  The apparent solution is to build
  # > your application with nightly and compile std locally (`-Zbuild-std`),
  # > but that is not desired for the majority of users.  [7339] suggests to
  # > provide a local `libgcc.a` as linker script, which simply redirects
  # > linking to `libunwind` instead - and that has proven to work fine so
  # > far.
  # >
  # > Instead of shipping this file with the crate or writing it to an existing
  # > link-search directory on the system, we write it to a new directory that
  # > can be easily passed or removed to `rustc`, say in the event that a user
  # > switches to an older NDK and builds without cleaning.  For this we need
  # > to switch from `cargo build` to `cargo rustc`, but the existing
  # > arguments and desired workflow remain identical.
  # >
  # > [85806]: rust-lang/rust#85806
  # > [7339]: termux/termux-packages#7339 (comment)

  fake-libgcc-gen = arch: pkgs.stdenv.mkDerivation {
    pname = "fake-libgcc";
    version = "0.1.0";

    dontUnpack = true;

    installPhase = ''
      mkdir -p $out/lib
      # on different architectures there will be different (but only a single one) libunwind.a for the given target
      # so use `find` and symlink it
      ln -s "`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt | grep ${arch}/libunwind.a`" $out/lib/libgcc.a
    '';
  };

  fake-libgcc-x86_64 = fake-libgcc-gen "x86_64";
  fake-libgcc-aarch64 = fake-libgcc-gen "aarch64";
  fake-libgcc-arm = fake-libgcc-gen "arm";
  fake-libgcc-i386 = fake-libgcc-gen "i386";



  # All the environment variables we need for all android cross compilation targets
  androidCrossEnvVars = ''

    export ROCKSDB_COMPILE=true 
    # Note: rockdb seems to require uint128_t, which is not supported on 32-bit Android: https://stackoverflow.com/a/25819240/134409 (?)
    export LLVM_CONFIG_PATH="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/llvm-config$`"

    export CC_armv7_linux_androideabi="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang$`"
    export CXX_armv7_linux_androideabi="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang++$`"
    export LD_armv7_linux_androideabi="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/ld$`"
    export LDFLAGS_armv7_linux_androideabi="-L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/arm-linux-androideabi/30$` -L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/arm-linux-androideabi$` -L ${fake-libgcc-arm}/lib"

    export CC_aarch64_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang$`"
    export CXX_aarch64_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang++$`"
    export LD_aarch64_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/ld$`"
    export LDFLAGS_aarch64_linux_android="-L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/aarch64-linux-android/30$` -L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/aarch64-linux-android$` -L ${fake-libgcc-aarch64}/lib"

    export CC_x86_64_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang$`"
    export CXX_x86_64_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang++$`"
    export LD_x86_64_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/ld$`"
    export LDFLAGS_x86_64_linux_android="-L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/x86_64-linux-android/30$` -L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/x86_64-linux-android$` -L ${fake-libgcc-x86_64}/lib"

    export CC_i686_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang$`"
    export CXX_i686_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/clang++$`"
    export LD_i686_linux_android="`find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ | grep bin/ld$`"
    export LDFLAGS_i686_linux_android="-L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/i686-linux-android/30$` -L `find ${androidSdk}/share/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/ -type d | grep sysroot/usr/lib/i686-linux-android$` -L ${fake-libgcc-i386}/lib"
  '';

  # Definitions of all the cross-compilation targets we support.
  # Later mapped over to conveniently loop over all possibilities.
  crossTargets =
    builtins.mapAttrs
      (attr: target: { name = attr; extraEnvs = ""; } // target)
      {
        "wasm32-unknown-unknown" = {
          extraEnvs = wasm32CrossEnvVars;
        };
        "armv7-linux-androideabi" = {
          extraEnvs = androidCrossEnvVars;
        };
        "aarch64-linux-android" = {
          extraEnvs = androidCrossEnvVars;
        };
        "i686-linux-android" = {
          extraEnvs = androidCrossEnvVars;
        };
        "x86_64-linux-android" = {
          extraEnvs = androidCrossEnvVars;
        };
      };

  fenixChannel = fenix.packages.${system}.stable;
  fenixChannelNightly = fenix.packages.${system}.latest;

  fenixToolchain = (fenixChannel.withComponents [
    "rustc"
    "cargo"
    "clippy"
    "rust-analysis"
    "rust-src"
    "llvm-tools-preview"
  ]);

  fenixToolchainNightly = (fenixChannelNightly.withComponents [
    "rustc"
    "cargo"
    "clippy"
    "rust-analysis"
    "rust-src"
    "llvm-tools-preview"
  ]);

  fenixToolchainDocNightly = fenixChannelNightly.withComponents [
    "cargo"
    "rustc"
  ];

  fenixToolchainRustfmt = (fenixChannelNightly.withComponents [
    "rustfmt"
  ]);

  fenixToolchainCargoFmt = (fenixChannelNightly.withComponents [
    "cargo"
    "rustfmt"
  ]);

  fenixToolchainCrossAll = with fenix.packages.${system}; combine ([
    stable.cargo
    stable.rustc
  ] ++ (lib.attrsets.mapAttrsToList
    (attr: target: targets.${target.name}.stable.rust-std)
    crossTargets));

  fenixToolchainCrossWasm = with fenix.packages.${system}; combine ([
    stable.cargo
    stable.rustc
    targets.wasm32-unknown-unknown.stable.rust-std
  ]);

  fenixToolchainCross = builtins.mapAttrs
    (attr: target: with fenix.packages.${system}; combine [
      stable.cargo
      stable.rustc
      targets.${target.name}.stable.rust-std
    ])
    crossTargets
  ;
in
{ inherit crossTargets androidCrossEnvVars wasm32CrossEnvVars fenixToolchain fenixToolchainNightly fenixChannel fenixToolchainRustfmt fenixToolchainCargoFmt fenixToolchainDocNightly fenixToolchainCrossAll fenixToolchainCrossWasm fenixToolchainCross; }
