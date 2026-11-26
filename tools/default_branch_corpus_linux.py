#!/usr/bin/env python3
"""Run one linked default-branch first-parent corpus through pinned R3."""
from pathlib import Path
import sys

from tools.current_corpus_linux import run_current
from tools.r3_linux_handoff import need


def main(argv=None) -> None:
    args = sys.argv[1:] if argv is None else argv
    need(len(args) == 11,
         'usage: default_branch_corpus_linux RELEASE_LOCK MANIFEST PREVIOUS '
         'CURRENT GAP IDENTITY INVENTORY SOURCE_CHECKOUT CONTROL_CHECKOUT '
         'R3_RUN_ROOT RUN_ID')
    (lock, manifest, previous, current, gap, identity, inventory,
     source, control, root) = map(Path, args[:10])
    run_current(lock, manifest, root, args[10],
                default_branch_context=(previous, current, gap, identity,
                                        inventory, source, control))


if __name__ == '__main__':
    main()
