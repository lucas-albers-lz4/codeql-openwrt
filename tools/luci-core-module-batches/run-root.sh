#!/usr/bin/env bash
# Creates one exclusive, physical run root before any log or output is opened.
create_run_root() {
  local run=$1
  local canonical
  canonical=$(python3 - "$run" <<'PY_CANON'
import pathlib,sys
print(pathlib.Path(sys.argv[1]).resolve(strict=False))
PY_CANON
  )
  [[ "$run" = /* && ! -e "$run" && "$canonical" == "$run" ]] || {
    echo 'run path must be absent, absolute and physical' >&2
    return 2
  }
  # mkdir without -p is the exclusivity boundary; a concurrent second launch fails here.
  mkdir "$run" || return 2
  mkdir -p "$run/tmp" "$run/home" "$run/output"
}
