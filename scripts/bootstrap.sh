#!/usr/bin/env bash
# shellcheck disable=SC2143

if ! command -v nix &>/dev/null ; then
  >&2 echo "❌ 'nix' not installed"
  >&2 echo "Please go to: https://nixos.org/download.html"
  >&2 echo "and use \"Nix: the package manager\" instructions to install it."
  >&2 echo "Most likely you just need to run: 'sh <(curl -L https://nixos.org/nix/install) --daemon'"
  >&2 echo ""
  >&2 echo "Re-run $0 after 'nix' is installed"
echo
  >&2 echo "✔️  'nix' installed"
fi

if [ -e ".direnv" ] ; then
  >&2 echo "✔️  'direnv allow' set"
else
  >&2 echo "❌ 'direnv allow' not set - not critical (please run 'direnv allow')"
fi

if [ -z "$(nix show-config | grep experimental-features | grep  flakes)" ] || [ -z "$(nix show-config | grep experimental-features | grep nix-command)" ] ; then
  >&2 echo "❌ Nix flakes not enabled - not critical (add 'experimental-features = nix-command flakes' to '$HOME/.config/nix/nix.conf')"
  nix_cmd="nix --experimental-features 'nix-command flakes'"
else
  >&2 echo "✔️  Nix flakes enabled"
  nix_cmd="nix"
fi

if [ -z "$(nix show-config | grep substituters | grep fedimint)" ]; then
  >&2 echo "❌ Fedimint CI binary cache not enabled - not critical (run '$nix_cmd develop .#bootstrap -c cachix use fedimint')"
else
  >&2 echo "✔️  Fedimint CI binary cache enabled"
fi


if [ -e "./target/debug/fedimintd" ]; then
  >&2 echo "✔️  fedimintd built already"
else
  >&2 echo "❌ fedimintd not built already - building..."
  $nix_cmd develop -c cargo check
  $nix_cmd develop -c cargo build
fi

>&2 echo ""
>&2 echo "Bootstrap complete."
>&2 echo "Use '$nix_cmd develop' to start the dev shell"
