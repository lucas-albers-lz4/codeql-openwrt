#!/usr/bin/env python3
"""Package only manifest-validated Statistics evidence with a 512 MiB cap."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('safe_package', HERE.parent / 'luci-app-metadata-probe' / 'package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
package.MAX_TOTAL = 512 * 1024 * 1024

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', required=True, type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps({'archive_sha256': package.create(args.output_root, args.archive)}, sort_keys=True))

if __name__ == '__main__':
    main()
