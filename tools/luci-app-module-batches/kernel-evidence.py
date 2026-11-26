"""Validate and retain the pinned x86_64 kernel prerequisite for the app batch."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
compare_spec = importlib.util.spec_from_file_location('app_batch_compare', HERE / 'compare.py')
base_compare = importlib.util.module_from_spec(compare_spec)
compare_spec.loader.exec_module(base_compare)
archive = base_compare.archive

KERNEL_VERSION = '6.12.116'
KERNEL_REL = f'build_dir/target-x86_64_musl/linux-x86_64/linux-{KERNEL_VERSION}'
DATA_PREFIX = f'lib/modules/{KERNEL_VERSION}/'
LINUX_KERNEL = HERE.parent / 'luci-statistics-batch' / 'kernel.py'
spec = importlib.util.spec_from_file_location('pinned_kernel_inventory', LINUX_KERNEL)
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def physical_file(path, root, nonempty=False):
    path, root = Path(path), Path(root).resolve(strict=True)
    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        raise ValueError('kernel evidence path must be absolute and canonical')
    try:
        rel = path.relative_to(root)
    except ValueError as exc:
        raise ValueError('kernel evidence path outside trusted root') from exc
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('kernel evidence path contains symlink: ' + str(current))
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('kernel evidence must be a unique regular file: ' + str(path))
    data = path.read_bytes()
    if nonempty and not data:
        raise ValueError('kernel evidence file is empty: ' + str(path))
    return data


def write_json_exclusive(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def run_paths(run_root):
    run = Path(run_root)
    if not run.is_absolute() or run.resolve(strict=True) != run or run.is_symlink():
        raise ValueError('run root must be a physical absolute directory')
    ow = run / 'openwrt'
    if not ow.is_dir() or ow.is_symlink() or ow.resolve(strict=True) != ow:
        raise ValueError('OpenWrt checkout path is not physical')
    out = run / 'output'
    if not out.is_dir() or out.is_symlink() or out.resolve(strict=True) != out:
        raise ValueError('output path is not a physical run-owned directory')
    expected = ow / KERNEL_REL
    stamps = sorted((ow / 'build_dir').rglob('.modules'))
    roots = [p.parent for p in stamps if p.is_file()]
    if roots != [expected] or expected.is_symlink() or expected.resolve(strict=True) != expected:
        raise ValueError('expected exactly one physical pinned x86_64 kernel build root')
    return run, ow, expected


def capture_kernel(run_root, config_sha256):
    run, ow, root = run_paths(run_root)
    inventory = kernel.inventory(root, run)
    if inventory['kernel_root'] != str(root):
        raise ValueError('kernel inventory root differs')
    config = physical_file(ow / '.config', ow, True)
    if digest(config) != config_sha256:
        raise ValueError('frozen OpenWrt config digest differs')
    out = run / 'output'
    evidence_dir = out / 'kernel-evidence'
    evidence_dir.mkdir(mode=0o755)
    file_paths = ('.config', '.modules', '.vermagic', 'modules.builtin',
                  'modules.builtin.modinfo', 'include/config/kernel.release')
    retained_files = {}
    for rel in file_paths:
        source = root / rel
        data = physical_file(source, root, rel != '.modules')
        dest = evidence_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(data)
        retained_files[rel] = {'sha256': digest(data), 'size': len(data),
                               'mode': format(stat.S_IMODE(source.stat().st_mode), '04o')}
    receipt = {'schema': 'luci-app-kernel-inventory-v1', 'openwrt_commit': base_compare.OPENWRT_SHA,
               'config_sha256': config_sha256, 'kernel_release': KERNEL_VERSION,
               'inventory': inventory, 'retained_files': retained_files}
    write_json_exclusive(out / 'kernel-inventory-before-package.json', receipt)
    return receipt


def reject_diagnostics(run, phase):
    data = b''
    for ext in ('stdout', 'stderr'):
        path = run / 'output' / f'{phase}.{ext}'
        data += physical_file(path, run / 'output') + b'\n'
    kernel.reject_empty_package_diagnostic(data)


def kernel_ipk_inventory(run, root):
    run, ow, root = Path(run), Path(run) / 'openwrt', Path(root)
    directory = ow / 'bin/targets/x86/64/packages'
    base_compare.physical_under(directory, run, 'kernel package output directory')
    if not directory.is_dir():
        raise ValueError('kernel package output directory is missing')
    paths = sorted(directory.glob('kernel_*.ipk'))
    rows = {}
    kernel_paths = []
    for path in paths:
        data = physical_file(path, ow, True)
        rows[path.name] = {'sha256': digest(data), 'size': len(data)}
        kernel_paths.append((path, data))
    if len(kernel_paths) != 1:
        raise ValueError('kernel IPK output is missing or ambiguous')
    magic = physical_file(root / '.vermagic', root, True).strip().decode('ascii')
    if not re.fullmatch(r'[0-9a-f]{32}', magic):
        raise ValueError('kernel vermagic differs')
    version = f'{KERNEL_VERSION}~{magic}-r1'
    version_bytes = physical_file(ow / 'staging_dir/target-x86_64_musl/kernel.version', ow, True)
    if version_bytes != (version + '\n').encode():
        raise ValueError('staged kernel.version differs from kernel vermagic')
    kernel_path, data = kernel_paths[0]
    if kernel_path != directory / f'kernel_{version}_x86_64.ipk':
        raise ValueError('kernel IPK filename differs from kernel version')
    control, members, outer = archive.read_ipk(data)
    fields = base_compare.base.control_from_rows(control)
    if fields != {'Package': 'kernel', 'Version': version, 'Architecture': 'x86_64'}:
        raise ValueError('kernel IPK control identity differs')
    builtin = DATA_PREFIX + 'modules.builtin'
    modinfo = DATA_PREFIX + 'modules.builtin.modinfo'
    for member in (builtin, modinfo):
        if (member not in members or members[member]['type'] != 'file' or
                members[member]['mode'] != 0o644):
            raise ValueError('kernel IPK metadata member differs: ' + member)
    source_builtin = physical_file(root / 'modules.builtin', root, True)
    projected = b''.join(line.rsplit(b'/', 1)[-1] for line in source_builtin.splitlines(keepends=True))
    if members[builtin]['bytes'] != projected:
        raise ValueError('kernel IPK modules.builtin projection differs')
    return {'version': version, 'kernel_version_sha256': digest(version_bytes),
            'control': fields, 'ipk_path': str(kernel_path.relative_to(ow)),
            'ipk_sha256': digest(data), 'ipk_size': len(data), 'outer_members': outer,
            'data_members': archive.receipts(members), 'control_members': archive.receipts(control),
            'builtin_projection_sha256': digest(projected),
            'modinfo_sha256': digest(members[modinfo]['bytes']),
            'ipk_inventory': rows}


def retain_kernel_candidates(run_root):
    run = Path(run_root)
    ow = run / 'openwrt'
    directory = ow / 'bin/targets/x86/64/packages'
    retained_dir = run / 'output/kernel-evidence/kernel-ipks'
    retained_dir.mkdir(mode=0o755)
    inventory = []
    directory_state = 'missing'
    if directory.exists() or directory.is_symlink():
        base_compare.physical_under(directory, run, 'kernel package output directory')
        if not directory.is_dir():
            raise ValueError('kernel package output path is not a directory')
        directory_state = 'present'
        for source in sorted(directory.glob('kernel_*.ipk')):
            data = physical_file(source, ow, True)
            with (retained_dir / source.name).open('xb') as stream:
                stream.write(data)
            inventory.append({'path': str(source.relative_to(ow)), 'sha256': digest(data), 'size': len(data)})
    version_state = {'status': 'missing'}
    version_path = ow / 'staging_dir/target-x86_64_musl/kernel.version'
    if version_path.exists() or version_path.is_symlink():
        version_bytes = physical_file(version_path, ow, True)
        with (run / 'output/kernel-evidence/kernel.version').open('xb') as stream:
            stream.write(version_bytes)
        version_state = {'status': 'present', 'sha256': digest(version_bytes), 'size': len(version_bytes)}
    observed = {'schema': 'luci-app-kernel-package-candidates-v1', 'directory_status': directory_state,
                'ipks': inventory, 'kernel_version': version_state}
    write_json_exclusive(run / 'output/kernel-package-candidates.json', observed)
    return observed


def snapshot_package_output(run_root):
    run, _, _ = run_paths(run_root)
    return retain_kernel_candidates(run)


def validate_package(run_root, config_sha256):
    run, ow, root = run_paths(run_root)
    before_path = run / 'output/kernel-inventory-before-package.json'
    before = json.loads(physical_file(before_path, run / 'output', True))
    current = kernel.inventory(root, run)
    if before.get('inventory') != current or before.get('config_sha256') != config_sha256:
        raise ValueError('kernel inventory/config changed before kernel package validation')
    candidates = json.loads(physical_file(run / 'output/kernel-package-candidates.json', run / 'output', True))
    live_candidates = sorted(({'path': str(path.relative_to(ow)), 'sha256': digest(physical_file(path, ow, True)),
                               'size': path.stat().st_size}
                              for path in (ow / 'bin/targets/x86/64/packages').glob('kernel_*.ipk')),
                             key=lambda row: row['path'])
    if candidates.get('directory_status') != 'present' or candidates.get('ipks') != live_candidates:
        raise ValueError('retained kernel IPK candidates differ from package output')
    version_state = candidates.get('kernel_version', {})
    if version_state.get('status') != 'present':
        raise ValueError('kernel.version was not retained after package phase')
    live_version = physical_file(ow / 'staging_dir/target-x86_64_musl/kernel.version', ow, True)
    retained_version = physical_file(run / 'output/kernel-evidence/kernel.version', run / 'output', True)
    if (version_state != {'status': 'present', 'sha256': digest(live_version), 'size': len(live_version)}
            or retained_version != live_version):
        raise ValueError('retained kernel.version differs from package-phase observation')
    package = kernel_ipk_inventory(run, root)
    ipk = ow / package['ipk_path']
    retained_dir = run / 'output/kernel-evidence'
    retained_ipk = retained_dir / 'kernel.ipk'
    with retained_ipk.open('xb') as stream:
        stream.write(physical_file(ipk, ow, True))
    write_json_exclusive(run / 'output/kernel-package-inventory.json', package)
    write_json_exclusive(run / 'output/kernel-inventory-after-package.json', current)
    return package


def recheck(run_root):
    run, ow, root = run_paths(run_root)
    expected_inventory = json.loads(physical_file(run / 'output/kernel-inventory-after-package.json', run / 'output', True))
    current = kernel.inventory(root, run)
    if expected_inventory != current:
        raise ValueError('kernel build files changed after package prerequisite')
    expected = json.loads(physical_file(run / 'output/kernel-package-inventory.json', run / 'output', True))
    actual = kernel_ipk_inventory(run, root)
    if expected != actual:
        raise ValueError('kernel package outputs changed after package prerequisite')
    retained = physical_file(run / 'output/kernel-evidence/kernel.ipk', run / 'output', True)
    live = physical_file(ow / actual['ipk_path'], ow, True)
    if retained != live:
        raise ValueError('retained kernel IPK differs from build output')
    retained_version = physical_file(run / 'output/kernel-evidence/kernel.version', run / 'output', True)
    current_version = physical_file(ow / 'staging_dir/target-x86_64_musl/kernel.version', ow, True)
    if retained_version != current_version:
        raise ValueError('retained kernel.version differs from build output')
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('capture', 'snapshot-package', 'validate-package', 'recheck', 'diagnostics'))
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--config-sha256')
    parser.add_argument('--phase', choices=('kernel-compile', 'kernel-package-compile'))
    args = parser.parse_args()
    if args.action == 'capture':
        if not args.config_sha256:
            parser.error('capture requires --config-sha256')
        capture_kernel(args.run_root, args.config_sha256)
    elif args.action == 'snapshot-package':
        snapshot_package_output(args.run_root)
    elif args.action == 'validate-package':
        if not args.config_sha256:
            parser.error('validate-package requires --config-sha256')
        reject_diagnostics(args.run_root, 'kernel-package-compile')
        validate_package(args.run_root, args.config_sha256)
    elif args.action == 'recheck':
        recheck(args.run_root)
    else:
        if not args.phase:
            parser.error('diagnostics requires --phase')
        reject_diagnostics(args.run_root, args.phase)


if __name__ == '__main__':
    main()
