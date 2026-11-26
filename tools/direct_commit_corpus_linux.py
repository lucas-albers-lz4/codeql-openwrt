#!/usr/bin/env python3
"""Run one historical direct-commit corpus through the pinned R3 release."""
from pathlib import Path
import sys

from tools.current_corpus_linux import run_current
from tools.r3_linux_handoff import need


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    need(len(args) == 9,
         'usage: direct_commit_corpus_linux.py RELEASE_LOCK DIRECT_MANIFEST '
         'IDENTITY_RECEIPT ADMISSION_CHECK INVENTORY SOURCE_CHECKOUT '
         'CONTROL_CHECKOUT R3_RUN_ROOT RUN_ID')
    lock, manifest, identity, admission, inventory, source, control, root = map(Path, args[:8])
    run_current(lock, manifest, root, args[8],
                event_context=(identity, admission, inventory, source, control))


if __name__ == '__main__':
    main()
