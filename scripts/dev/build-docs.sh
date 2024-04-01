#!/usr/bin/env bash

set -euo pipefail

source "./scripts/_common.sh"

fm_index_md=${FM_RUSTDOC_INDEX_MD:-./docs/rustdoc-index.md}
index_html="${CARGO_BUILD_TARGET_DIR:-target}/doc/index.html"

export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -D warnings'
if cargo version | grep -q nightly ; then
  RUSTDOCFLAGS="$RUSTDOCFLAGS -Z unstable-options --enable-index-page"
  # broken: https://github.com/rust-lang/rust/issues/97881
  # RUSTDOCFLAGS="$RUSTDOCFLAGS --index-page ${FM_RUSTDOC_INDEX_MD:-./docs/rustdoc-index.md}"
fi
echo RUSTDOCFLAGS: "$RUSTDOCFLAGS"

cargo doc --exclude fedimint-fuzz --profile "$CARGO_PROFILE" --locked --workspace --no-deps --document-private-items

if [ -e "${index_html}" ]; then
  if command -v pandoc >/dev/null 2>/dev/null ; then
    # since `--index-page` is broken, improve our index page manually :/
    pandoc "$fm_index_md" > "${fm_index_md}.html"
    trap 'rm -f "${fm_index_md}.html"' EXIT

    sed -i 's#<title>Index of crates</title>#<title>Fedimint technical reference</title>#' "$index_html"

    awk -v insert_path="${fm_index_md}.html" '
      BEGIN {
        RS = ORS = "\0"; # Treat the file as a single record
        while ((getline line < insert_path) > 0) {
          content = content line "\n";
        }
        close(insert_path);
      }
      {
        sub(/<section id="main-content"/, content "&"); # Replace MARKER with insert.txt content + MARKER
        print;
      }' "$index_html" > "$index_html.tmp" && mv "$index_html.tmp" "$index_html"
  fi
fi
