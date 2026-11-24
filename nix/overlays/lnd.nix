final: prev: {
  # Remove when stable LND recognizes TAPROOT in getdeploymentinfo.script_flags.
  lnd = prev.lnd.overrideAttrs (
    finalAttrs: _: {
      version = "0.21.6-beta";
      src = final.fetchFromGitHub {
        owner = "lightningnetwork";
        repo = "lnd";
        rev = "v${finalAttrs.version}";
        hash = "sha256-khTu7oDifgbVWPVf2doP0EsJaCETUH6VXmLswkZ3jNo=";
      };
      vendorHash = "sha256-IHMuTwyc+aTPYECdfI5QCijFzXWuAQtZiDlZaLnhjcY=";
    }
  );
}
