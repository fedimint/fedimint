#!/usr/bin/env bash
yesterday=$(date -d "yesterday" +%s)
motd_ts_path=".config/flakebox/tmp/motd"

if [ ! -e "$motd_ts_path" ] || [ "$motd_ts_path" -ot "$yesterday" ]; then
mkdir -p "$(dirname "$motd_ts_path")"
touch "$motd_ts_path"
>&2 echo "🚧 In an enfort to improve documentation, we now require all structs and"
>&2 echo "🚧 and public methods to be documented with a docstring."
>&2 echo "🚧 See https://github.com/fedimint/fedimint/issues/3807"

fi

root="$(git rev-parse --show-toplevel)"
dot_git="$(git rev-parse --git-common-dir)"
if [[ ! -d "${dot_git}/hooks" ]]; then mkdir -p "${dot_git}/hooks"; fi
# fix old bug
if [[ -e "${dot_git}/hooks/comit-msg" || -L "${dot_git}/hooks/comit-msg" ]]; then
  rm -f "${dot_git}/hooks/comit-msg"
fi
hook="${dot_git}/hooks/commit-msg"
source="${root}/misc/git-hooks/commit-msg"
if [[ ! -e "${hook}" ]] || ! cmp -s "${source}" "${hook}"; then
  rm -f "${hook}"
  ln -sf "${source}" "${hook}"
fi

root="$(git rev-parse --show-toplevel)"
dot_git="$(git rev-parse --git-common-dir)"
if [[ ! -d "${dot_git}/hooks" ]]; then mkdir -p "${dot_git}/hooks"; fi
# fix old bug
if [[ -e "${dot_git}/hooks/pre-comit" || -L "${dot_git}/hooks/pre-comit" ]]; then
  rm -f "${dot_git}/hooks/pre-comit"
fi
hook="${dot_git}/hooks/pre-commit"
source="${root}/misc/git-hooks/pre-commit"
if [[ ! -e "${hook}" ]] || ! cmp -s "${source}" "${hook}"; then
  rm -f "${hook}"
  ln -sf "${source}" "${hook}"
fi

# set template
if [[ "$(git config --get commit.template || true)" != "misc/git-hooks/commit-template.txt" ]]; then
  git config commit.template misc/git-hooks/commit-template.txt
fi

if ! flakebox lint --silent; then
  >&2 echo "ℹ️  Project recommendations detected. Run 'flakebox lint' for more info."
fi

if [[ "$-" == *i* ]] && [[ -t 2 ]]; then
  >&2 echo "💡 Run 'just' for a list of available 'just ...' helper recipes"
fi
