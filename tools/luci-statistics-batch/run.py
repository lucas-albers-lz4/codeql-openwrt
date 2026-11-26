#!/usr/bin/env python3
"""Candidate normal Statistics build; no execution without exact-head review."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import platform
import shutil
import stat
import subprocess
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'luci-app-metadata-probe'))
import check
import run as metadata
sys.path.insert(0, str(HERE))
import compare
import kernel

CONFIG_SHA = 'cbff738c953271533651885c3759d6a5ba6b845c61b23a1e7aca7059f552d8ff'
GRAPH_SHAS = frozenset({
    '48bbf0a4525d53718fb8271f52857082e7917b09c268873706261b897ecf3b69',
    '2f934e455a22f63289ebb82e87f59866f002167dae7418b5ed5464cf6a608a80',
})
PHASE_TIMEOUTS = {'tools-install': 3600, 'toolchain-install': 4800,
                  'kernel-compile': 5400, 'kernel-package-compile': 3600,
                  'statistics-compile': 2400}

def host_preflight(probe):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('host must be Linux x86_64')
    available = shutil.disk_usage(probe.root).free
    meminfo = Path('/proc/meminfo').read_text()
    match = re.search(r'^MemTotal:\s+([0-9]+) kB$', meminfo, re.MULTILINE)
    if not match or int(match.group(1)) * 1024 < 8 * 1024**3:
        raise ValueError('host memory below 8 GiB')
    if available < 60 * 1024**3 or (os.cpu_count() or 0) < 2:
        raise ValueError('host disk below 60 GiB or fewer than two CPUs')
    facts = {'platform': platform.platform(), 'machine': platform.machine(),
             'memory_total_bytes': int(match.group(1)) * 1024,
             'disk_free_bytes': available, 'cpu_count': os.cpu_count()}
    with (probe.out / 'host-preflight.json').open('x') as f:
        json.dump(facts, f, indent=2, sort_keys=True)
        f.write('\n')

def capture_prerequisites(probe, source):
    source = Path(source)
    if not source.is_absolute() or source.resolve(strict=True) != source or not source.is_dir():
        raise ValueError('prerequisite log root must be physical')
    for name in ('apt-update.log', 'apt-update.time', 'apt-install.log', 'apt-install.time'):
        path = source / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 1024 * 1024:
            raise ValueError('prerequisite log exceeds limit: ' + name)
        data = check.physical_file(path, source, True)
        with (probe.out / name).open('xb') as output:
            output.write(data)

def frozen_metadata(probe, label, expected_graph=None):
    ow = probe.root / 'openwrt'
    captured = {}
    failures = []
    for name, path in (('config', ow / '.config'), ('packagedeps', ow / 'tmp/.packagedeps')):
        try:
            data = check.physical_file(path, ow, True)
        except Exception as exc:
            failures.append(name + ': ' + repr(exc))
            continue
        with (probe.out / ('metadata-' + label + '-' + name)).open('xb') as output:
            output.write(data)
        captured[name] = data
    if failures:
        raise ValueError('metadata snapshot failed: ' + repr(failures))
    config, graph = captured['config'], captured['packagedeps']
    if check.digest(config) != CONFIG_SHA:
        raise ValueError('frozen Statistics config differs')
    graph_sha = check.digest(graph)
    if expected_graph is None:
        if label != 'pre-build' or graph_sha not in GRAPH_SHAS:
            raise ValueError('initial Statistics graph not approved')
    elif expected_graph not in GRAPH_SHAS or graph_sha != expected_graph:
        raise ValueError('Statistics graph changed after initial lock')
    check.validate_final_config(config, 'statistics-only')
    check.validate_packagedeps(graph, 'statistics-only')
    return config, graph_sha

def source_preflight(probe, oracle):
    luci = probe.root / 'luci'
    for row in oracle['entries']:
        if row['package'] == 'luci-app-statistics':
            compare.batch.git_blob(luci, compare.LUCI_SHA, dict(row, git_blob=row['git_object']))
    data = subprocess.check_output(['git', '-C', str(luci), 'show', compare.LUCI_SHA + ':luci.mk'])
    if hashlib.sha256(data).hexdigest() != oracle['luci_mk_sha256']:
        raise ValueError('luci.mk source digest differs')

def post_sources(probe, label, expected):
    for name, (_, commit) in metadata.PINS.items():
        repo = probe.root / name
        head = probe.git(name + '-head-after-' + label, repo, 'rev-parse', 'HEAD', 'HEAD^{tree}').decode().splitlines()
        if head != [commit, expected[name]['tree']]:
            raise ValueError('source revision or tree changed: ' + name)
        flag = '--untracked-files=no' if name == 'openwrt' else '--untracked-files=all'
        status = probe.git(name + '-status-after-' + label, repo, 'status', '--porcelain=v1', flag)
        if status:
            raise ValueError('source changed: ' + name)

def invoke_make(probe, label, target, sources, graph_lock):
    ow = probe.root / 'openwrt'
    frozen_metadata(probe, label + '-before', graph_lock)
    argv = ['/usr/bin/time', '-v', '-o', str(probe.out / (label + '.time')), 'make', '-j2', target, 'V=s']
    phase_error = None
    try:
        probe.invoke(label, argv, ow, timeout=PHASE_TIMEOUTS[label])
    except Exception as exc:
        phase_error = repr(exc)
    post_errors = []
    if probe.quiescent:
        for name, action in (
            ('metadata', lambda: frozen_metadata(probe, label + '-after', graph_lock)),
            ('sources', lambda: post_sources(probe, label, sources)),
            ('consumer', lambda: probe.consumer_identity('after-' + label)),
            ('feed-luci', lambda: check.validate_link(ow / 'feeds/luci', probe.root / 'luci')),
            ('feed-packages', lambda: check.validate_link(ow / 'feeds/packages', probe.root / 'packages')),
            ('statistics-link', lambda: check.validate_link(ow / 'package/feeds/luci/luci-app-statistics', probe.root / 'luci/applications/luci-app-statistics')),
        ):
            try:
                action()
            except Exception as exc:
                post_errors.append(name + ': ' + repr(exc))
        try:
            report = check.physical_file(probe.out / (label + '.time'), probe.out, True)
            peak = re.search(rb'Maximum resident set size \(kbytes\): ([0-9]+)', report)
            if not peak:
                raise ValueError('time report lacks peak RSS')
            probe.phases.append({'label': label + '-time-report', 'sha256': check.digest(report),
                                 'peak_rss_kib': int(peak.group(1)), 'report_path': label + '.time'})
        except Exception as exc:
            post_errors.append('time-report: ' + repr(exc))
        try:
            stderr = check.physical_file(probe.out / (label + '.stderr'), probe.out)
            stdout = check.physical_file(probe.out / (label + '.stdout'), probe.out)
            if label == 'kernel-package-compile':
                kernel.reject_missing_module(stdout)
                kernel.reject_missing_module(stderr)
            else:
                kernel.reject_empty_package_diagnostic(stdout + b'\n' + stderr)
        except Exception as exc:
            post_errors.append('diagnostics: ' + repr(exc))
    else:
        post_errors.append('postguard withheld: process group may still be active')
    if phase_error or post_errors:
        raise RuntimeError('phase failure: ' + repr({'phase': phase_error, 'postguard': post_errors}))
    return stdout, stderr

def kernel_package_inventory(probe, kernel_root):
    ow = probe.root / 'openwrt'
    directory = ow / 'bin/targets/x86/64/packages'
    compare.physical_directory(directory, probe.root)
    paths = sorted(directory.glob('*.ipk'))
    kernel_paths = [p for p in paths if p.name.startswith('kernel_')]
    if not paths or len(kernel_paths) != 1:
        raise ValueError('kernel package output inventory missing or ambiguous')
    magic = check.physical_file(kernel_root / '.vermagic', kernel_root, True).strip().decode('ascii')
    if not re.fullmatch(r'[0-9a-f]{32}', magic):
        raise ValueError('kernel vermagic differs')
    version = '6.12.116~' + magic + '-r1'
    stage_version = check.physical_file(ow / 'staging_dir/target-x86_64_musl/kernel.version', ow, True)
    if stage_version != (version + '\n').encode():
        raise ValueError('staged kernel version differs')
    packages = {}
    for path in paths:
        data = check.physical_file(path, ow, True)
        packages[path.name] = {'sha256': check.digest(data), 'bytes': len(data)}
        if path == kernel_paths[0]:
            control, members, _ = compare.batch.archive.read_ipk(data)
            fields = compare.batch.base.control_from_rows(control)
            if fields != {'Package': 'kernel', 'Version': version, 'Architecture': 'x86_64'}:
                raise ValueError('kernel control identity differs')
            prefix = 'lib/modules/6.12.116/'
            builtin_path = prefix + 'modules.builtin'
            modinfo_path = prefix + 'modules.builtin.modinfo'
            for member in (builtin_path, modinfo_path):
                if member not in members or members[member]['type'] != 'file' or members[member]['mode'] != 0o644:
                    raise ValueError('kernel builtin metadata member differs: ' + member)
            source_builtin = check.physical_file(kernel_root / 'modules.builtin', kernel_root, True)
            projected = b''.join(line.rsplit(b'/', 1)[-1] for line in source_builtin.splitlines(keepends=True))
            if members[builtin_path]['bytes'] != projected:
                raise ValueError('kernel builtin projection differs')
            packages[path.name]['control'] = fields
            packages[path.name]['builtin_metadata'] = {member: {'sha256': check.digest(members[member]['bytes']), 'size': len(members[member]['bytes']), 'mode': '0644'} for member in (builtin_path, modinfo_path)}
    return packages

def run_build(probe):
    host_preflight(probe)
    result = probe.run()
    probe.metadata_result = result
    oracle = compare.load_oracle()
    source_preflight(probe, oracle)
    build_config, graph_lock = frozen_metadata(probe, 'pre-build')
    result['locked_graph_sha256'] = graph_lock
    for label, target in (('tools-install', 'tools/install'), ('toolchain-install', 'toolchain/install'), ('kernel-compile', 'target/linux/compile')):
        invoke_make(probe, label, target, result['source_before'], graph_lock)
    ow = probe.root / 'openwrt'
    roots = sorted({p.parent for p in (ow / 'build_dir').rglob('.modules')})
    if len(roots) != 1:
        raise ValueError('kernel build root must be unique')
    evidence = kernel.inventory(roots[0], probe.root)
    with (probe.out / 'kernel-inventory.json').open('x') as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
        f.write('\n')
    kernel_inputs = {
        'kernel-config': check.physical_file(roots[0] / '.config', roots[0], True),
        'kernel-modules-stamp': check.physical_file(roots[0] / '.modules', roots[0]),
        'kernel-vermagic': check.physical_file(roots[0] / '.vermagic', roots[0], True),
        'kernel-modules.builtin': check.physical_file(roots[0] / 'modules.builtin', roots[0], True),
        'kernel-modules.builtin.modinfo': check.physical_file(roots[0] / 'modules.builtin.modinfo', roots[0], True),
        'kernel-release': check.physical_file(roots[0] / 'include/config/kernel.release', roots[0], True),
    }
    for name, data in kernel_inputs.items():
        with (probe.out / name).open('xb') as f:
            f.write(data)
    # Retain physical kernel evidence before deciding the scoped warning policy.
    before = evidence
    kernel_stdout, kernel_stderr = invoke_make(probe, 'kernel-package-compile', 'package/kernel/linux/compile', result['source_before'], graph_lock)
    after = kernel.inventory(roots[0], probe.root)
    if after != before:
        raise ValueError('kernel inventory changed after package/kernel/linux compile')
    with (probe.out / 'kernel-inventory-after.json').open('x') as f:
        json.dump(after, f, indent=2, sort_keys=True)
        f.write('\n')
    kernel_dir = ow / 'bin/targets/x86/64/packages'
    compare.physical_directory(kernel_dir, probe.root)
    kernel_ipks = sorted(kernel_dir.glob('kernel_*.ipk'))
    if len(kernel_ipks) != 1:
        raise ValueError('kernel package output inventory missing or ambiguous')
    evidence_files = {
        'kernel.ipk': check.physical_file(kernel_ipks[0], ow, True),
        'kernel-version': check.physical_file(ow / 'staging_dir/target-x86_64_musl/kernel.version', ow, True),
    }
    for name, data in evidence_files.items():
        with (probe.out / name).open('xb') as f:
            f.write(data)
    kernel_packages = kernel_package_inventory(probe, roots[0])
    with (probe.out / 'kernel-packages.json').open('x') as f:
        json.dump(kernel_packages, f, indent=2, sort_keys=True)
        f.write('\n')
    sha_kernel_config = check.digest(kernel_inputs['kernel-config'])
    warnings = kernel.classify_scoped_warnings(kernel_stdout, kernel_stderr, build_config,
                                               sha_kernel_config,
                                               kernel_inputs['kernel-vermagic'].strip().decode('ascii'))
    disposition = {'scope': 'known globally selected DRM packages outside audited Statistics dependency overapproximation; not an image completeness claim',
                   'warnings': warnings, 'build_config_sha256': check.digest(build_config),
                   'kernel_config_sha256': sha_kernel_config,
                   'kernel_vermagic': kernel_inputs['kernel-vermagic'].strip().decode('ascii')}
    with (probe.out / 'kernel-warning-disposition.json').open('x') as f:
        json.dump(disposition, f, indent=2, sort_keys=True)
        f.write('\n')
    result['kernel_warning_disposition'] = disposition
    invoke_make(probe, 'statistics-compile', 'package/feeds/luci/luci-app-statistics/compile', result['source_before'], graph_lock)
    config, _ = frozen_metadata(probe, 'statistics-comparison', graph_lock)
    prepared = ow / 'build_dir/target-x86_64_musl/luci-app-statistics'
    stage = prepared / 'ipkg-all/luci-app-statistics'
    ipk_dir = ow / 'bin/packages/x86_64/luci'
    compare.physical_directory(ipk_dir, probe.root)
    paths = sorted(ipk_dir.glob('luci-app-statistics_*.ipk'))
    expected = ipk_dir / 'luci-app-statistics_26.205.85817~58d43e5_all.ipk'
    if paths != [expected]:
        raise ValueError('Statistics IPK path is missing or ambiguous')
    ipk = check.physical_file(expected, ow, True)
    with (probe.out / 'luci-app-statistics.ipk').open('xb') as f:
        f.write(ipk)
    receipt = compare.compare(probe.root / 'luci', prepared, stage, ipk, oracle, probe.root, config)
    receipt.update({'ipk_sha256': check.digest(ipk), 'config_sha256': check.digest(config),
                    'oracle_sha256': compare.ORACLE_SHA, 'graph_sha256': graph_lock, 'kernel_inventory_sha256': check.digest(check.physical_file(probe.out / 'kernel-inventory.json', probe.out, True))})
    with (probe.out / 'statistics-comparison.json').open('x') as f:
        json.dump(receipt, f, indent=2, sort_keys=True)
        f.write('\n')
    frozen_metadata(probe, 'final', graph_lock)
    if kernel.inventory(roots[0], probe.root) != before or kernel_package_inventory(probe, roots[0]) != kernel_packages:
        raise ValueError('kernel evidence changed after Statistics target')
    result['status'] = 'statistics_package_compared_review_required'
    result['scope'] = 'source/prepared/stage/IPK comparison; no installation, extraction or runtime claim'
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--consumer-commit', required=True)
    parser.add_argument('--prereq-root', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o022)
    probe = metadata.Probe(args.root, args.consumer_commit, 'statistics-only')
    # Also bind helper subprocesses (including Git object reads) to this environment.
    os.environ.clear()
    os.environ.update(probe.env)
    result = {'status': 'failed', 'scope': 'Statistics candidate build; retained evidence requires independent review'}
    try:
        capture_prerequisites(probe, args.prereq_root)
        result = run_build(probe)
    except Exception as exc:
        result.update(getattr(probe, 'metadata_result', {}))
        result['status'] = 'failed'
        result['scope'] = 'Statistics candidate failed; retained evidence requires independent review'
        result['failure'] = repr(exc)
        result['diagnostics'] = probe.diags
        result['profile'] = 'statistics-only'
        result['requested_app_packages'] = ['luci-app-statistics']
        metadata.capture_failure_evidence(probe, result)
    output_ok = probe.finish(result)
    if result['status'] != 'statistics_package_compared_review_required' or not output_ok:
        raise SystemExit('candidate failed; inspect retained result')
    print('Statistics package evidence retained; independent review required')

if __name__ == '__main__':
    main()
