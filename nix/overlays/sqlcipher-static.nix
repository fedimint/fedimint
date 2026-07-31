final: prev: {
  # `pkgsStatic.sqlcipher` does not build since sqlcipher moved to sqlite's
  # autosetup build (4.6.1 -> 4.14.0): the TCL extension links against the
  # shared library, so `make` builds `libsqlite3.so` even though `configure`
  # was told not to, and linking a shared object fails in a static musl
  # environment.
  #
  # Drop TCL, and with it the shared library fixups in the upstream
  # `postInstall`, which have nothing left to operate on.
  sqlcipher = prev.sqlcipher.overrideAttrs (
    prevAttrs:
    prev.lib.optionalAttrs prev.stdenv.hostPlatform.isStatic {
      configureFlags = prevAttrs.configureFlags ++ [ "--disable-tcl" ];

      postInstall = ''
        mv $out/bin/{sqlite3,sqlcipher}
        mkdir $out/include/sqlcipher
        mv $out/include/sqlite3.h $out/include/sqlcipher/sqlite3.h
        mv $out/include/sqlite3ext.h $out/include/sqlcipher/sqlite3ext.h
        mv $out/lib/lib{sqlite3,sqlcipher}.a
        mv $out/lib/pkgconfig/{sqlite3,sqlcipher}.pc
        mv $out/share/man/man1/{sqlite3,sqlcipher}.1
        substituteInPlace $out/lib/pkgconfig/sqlcipher.pc \
          --replace-fail "-lsqlite3" "-lsqlcipher" \
          --replace-fail "-lz" "-lz -lcrypto" \
          --replace-fail "includedir}" "includedir}/sqlcipher"
      '';
    }
  );
}
