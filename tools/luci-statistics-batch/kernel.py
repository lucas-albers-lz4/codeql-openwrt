#!/usr/bin/env python3
"""Inventory a freshly compiled kernel, without claiming module coverage."""
import hashlib
import json
from pathlib import Path
import re
import stat

def regular(root, relative, nonempty=True):
    root = Path(root)
    if Path(relative).is_absolute():
        raise ValueError('unsafe kernel path')
    cur = root
    for item in Path(relative).parts:
        if item in ('', '.', '..'):
            raise ValueError('unsafe kernel path')
        cur = cur / item
        if cur.is_symlink():
            raise ValueError('kernel path alias: ' + str(cur))
    info = cur.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('kernel evidence must be unique regular file: ' + str(cur))
    data = cur.read_bytes()
    if nonempty and not data:
        raise ValueError('empty kernel evidence: ' + str(cur))
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': format(stat.S_IMODE(info.st_mode), '04o')}

def inventory(kernel, run):
    kernel, run = Path(kernel), Path(run)
    if not kernel.is_absolute() or not run.is_absolute() or run.resolve(strict=True) != run:
        raise ValueError('run or kernel root is not physical')
    try:
        relative = kernel.relative_to(run)
    except ValueError as exc:
        raise ValueError('kernel root outside run') from exc
    cur = run
    for item in relative.parts:
        cur = cur / item
        if cur.is_symlink() or not cur.is_dir():
            raise ValueError('kernel root is aliased or missing')
    if kernel.resolve(strict=True) != kernel:
        raise ValueError('kernel root is not physical')
    result = {p: regular(kernel, p, p != '.modules') for p in ('.config', '.modules', '.vermagic', 'modules.builtin', 'modules.builtin.modinfo', 'include/config/kernel.release')}
    if b'CONFIG_X86_64=y' not in (kernel / '.config').read_bytes().splitlines():
        raise ValueError('kernel config is not x86_64')
    if not re.fullmatch(rb'6\.12\.116(?:[-+._A-Za-z0-9]*)?\n', (kernel / 'include/config/kernel.release').read_bytes()):
        raise ValueError('kernel release is not pinned 6.12.116')
    if not re.fullmatch(rb'[0-9a-f]{32}\n?', (kernel / '.vermagic').read_bytes()):
        raise ValueError('kernel vermagic is missing or malformed')
    modules = {}
    for path in sorted(kernel.rglob('*.ko')):
        relative = path.relative_to(kernel).as_posix()
        modules[relative] = regular(kernel, relative)
    return {'kernel_root': str(kernel), 'files': result, 'modules': modules,
            'limitation': 'inventory only; selected package FILES and builtin applicability require review'}

def reject_empty_package_diagnostic(data):
    if b'is not available in the kernel config - generating empty package' in data:
        raise ValueError('selected kernel package generated empty')
    if re.search(rb"ERROR: module '[^\n]*' is missing\.", data):
        raise ValueError('required kernel module missing')
