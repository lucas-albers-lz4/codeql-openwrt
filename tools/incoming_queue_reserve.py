#!/usr/bin/env python3
"""Explicit one-PR reservation in an existing private local queue.

This command does not dispatch a scan, sign a start, or complete queue work.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from incoming_poll import PollError, check, unique_object
from incoming_queue import open_queue, reserve_exact_pr


def load_prepared(path):
    info = path.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
          'prepared input must be an unaliased regular file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(descriptor)
        check(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
              (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
              'prepared input changed before read')
        chunks = []
        remaining = 65_537
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
    finally:
        os.close(descriptor)
    check(len(raw) <= 65_536, 'prepared input exceeds byte limit')
    return json.loads(raw, object_pairs_hook=unique_object)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--prepared-inputs', required=True, type=Path)
    parser.add_argument('--expected-sequence', required=True, type=int)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--retry', action='store_true',
                        help='reserve a previously attempted pending PR only after all first attempts')
    args = parser.parse_args()
    try:
        check(args.expected_sequence >= 0 and isinstance(args.expected_sha256, str) and
              len(args.expected_sha256) == 64 and
              all(c in '0123456789abcdef' for c in args.expected_sha256),
              'invalid queue predecessor')
        prepared = load_prepared(args.prepared_inputs)
        db = open_queue(args.database)
        try:
            result, digest = reserve_exact_pr(
                db, (args.expected_sequence, args.expected_sha256), prepared,
                datetime.now(timezone.utc).isoformat(), retry=args.retry)
        finally:
            db.close()
        print(json.dumps({'sequence': result['sequence'], 'sha256': digest,
                          'event_id': result['event_id'], 'status': result['status'],
                          'attempts_before': result['attempts_before'],
                          'snapshot_sha256': result['snapshot_sha256']}))
        return 0
    except (PollError, ValueError, TypeError, KeyError, OSError, sqlite3.Error, RecursionError) as exc:
        print('manual reservation rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
