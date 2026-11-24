#!/usr/bin/env python3
"""Run an API-bound incoming corpus through an already verified R3 release."""
from pathlib import Path
import sys

from tools.current_corpus_linux import run_current
from tools.r3_linux_handoff import need


if __name__ == "__main__":
    need(len(sys.argv) == 8,
         "usage: event_corpus_linux.py RELEASE_LOCK EVENT_MANIFEST EVENT_RECEIPT "
         "CANDIDATE_INVENTORY SOURCE_CHECKOUT R3_RUN_ROOT RUN_ID")
    run_current(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[6]), sys.argv[7],
                event_context=(Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])))
