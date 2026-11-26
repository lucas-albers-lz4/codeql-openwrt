#!/usr/bin/env bash
# Emit only fixed, profile-specific workflow paths; creates no files.
set -Eeuo pipefail
[[ $# == 2 ]] || { echo 'expected profile and physical runner temp' >&2; exit 2; }
profile=$1
base=$2
[[ "$base" != *$'\n'* && "$base" != *$'\r'* && "$base" == /* && -d "$base" && ! -L "$base" && $(realpath "$base") == "$base" ]] || {
  echo 'runner temp must be a physical absolute directory' >&2
  exit 2
}
case "$profile" in
  joint) suffix='' ;;
  statistics-only) suffix='-statistics-only' ;;
  *) echo 'unknown metadata profile' >&2; exit 2 ;;
esac
printf 'root=%s/issue173-app-metadata%s\n' "$base" "$suffix"
printf 'archive=%s/issue173-app-metadata%s-evidence.tar\n' "$base" "$suffix"
printf 'suffix=%s\n' "$suffix"
