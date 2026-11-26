#!/usr/bin/env python3
"""Operator-only recovery of an unstarted stale PR reservation.

This checks caller-supplied hosted API files but does not authenticate their
GitHub custody. It never signs a scan start or completion.
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
from incoming_queue import open_queue, recover_stale_reserved_pr


def load_evidence(path):
    info = path.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
          'recovery evidence must be an unaliased regular file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        check(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
              (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino) and
              opened.st_size <= 65_536, 'recovery evidence changed before read')
        chunks = []
        remaining = 65_537
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        check(len(raw) <= 65_536, 'recovery evidence exceeds byte limit')
        after = os.fstat(descriptor)
        check((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
              'recovery evidence changed during read')
        json.loads(raw, object_pairs_hook=unique_object)
        return raw
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--pull-api', required=True, type=Path)
    parser.add_argument('--run-api', required=True, type=Path)
    parser.add_argument('--jobs-api', required=True, type=Path)
    parser.add_argument('--dispatch-inputs', required=True, type=Path)
    parser.add_argument('--expected-sequence', required=True, type=int)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    try:
        check(args.expected_sequence >= 0 and isinstance(args.expected_sha256, str) and
              len(args.expected_sha256) == 64 and
              all(c in '0123456789abcdef' for c in args.expected_sha256),
              'invalid queue predecessor')
        raw_files = {'pull': load_evidence(args.pull_api),
                     'run': load_evidence(args.run_api),
                     'jobs': load_evidence(args.jobs_api),
                     'dispatch': load_evidence(args.dispatch_inputs)}
        db = open_queue(args.database)
        try:
            result, digest = recover_stale_reserved_pr(
                db, (args.expected_sequence, args.expected_sha256), raw_files,
                datetime.now(timezone.utc).isoformat())
        finally:
            db.close()
        print(json.dumps({'sequence': result['sequence'], 'sha256': digest,
                          'status': result['status'], 'event_id': result['event_id'],
                          'observed_head': result['observed_head']}))
        return 0
    except (PollError, ValueError, KeyError, IndexError, TypeError, AttributeError, OSError,
            sqlite3.Error, json.JSONDecodeError) as exc:
        print('stale reservation recovery rejected: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
