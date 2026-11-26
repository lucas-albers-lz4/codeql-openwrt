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

EMPTY_WARNING = re.compile(rb'^WARNING: .+ is not available in the kernel config - generating empty package$')
MISSING_ERROR = re.compile(rb"^ERROR: module '[^\r\n]+' is missing\.$")
KNOWN_EMPTY = {
    b'WARNING: kmod-drm-exec is not available in the kernel config - generating empty package',
    b'WARNING: kmod-drm-suballoc-helper is not available in the kernel config - generating empty package',
}
AUDITED_KERNEL_CONFIG = '10bcab859188cc3602488c42507780a0de7c6336e537494a475db9526476591f'
AUDITED_VERMAGIC = 'd06fc8e744142971fdfa96b50c6d006f'
AUDITED_BUILD_CONFIG = 'cbff738c953271533651885c3759d6a5ba6b845c61b23a1e7aca7059f552d8ff'

def reject_missing_module(data):
    if any(MISSING_ERROR.fullmatch(line) for line in data.splitlines()):
        raise ValueError('required kernel module missing')

def empty_warnings(data):
    return [line for line in data.splitlines() if EMPTY_WARNING.fullmatch(line)]

def reject_empty_package_diagnostic(data):
    reject_missing_module(data)
    if empty_warnings(data):
        raise ValueError('selected kernel package generated empty')

def classify_scoped_warnings(stdout, stderr, build_config, kernel_config_sha, vermagic):
    reject_missing_module(stdout)
    reject_missing_module(stderr)
    out, err = empty_warnings(stdout), empty_warnings(stderr)
    if out or len(err) != len(set(err)) or (err and set(err) != KNOWN_EMPTY):
        raise ValueError('unapproved empty kernel package diagnostic')
    if err:
        selected = build_config.splitlines()
        if (hashlib.sha256(build_config).hexdigest() != AUDITED_BUILD_CONFIG or
                selected.count(b'CONFIG_PACKAGE_kmod-drm-exec=y') != 1 or
                selected.count(b'CONFIG_PACKAGE_kmod-drm-suballoc-helper=y') != 1 or
                selected.count(b'CONFIG_PACKAGE_kmod-drm-i915=y') != 1 or
                kernel_config_sha != AUDITED_KERNEL_CONFIG or vermagic != AUDITED_VERMAGIC):
            raise ValueError('known empty warnings lack audited config or kernel identity')
    return [line.decode('ascii') for line in err]
