#!/usr/bin/env python3
"""Verify retained released-scan summaries; does not rerun the producer."""
import hashlib
import json
import re
import stat
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
MANIFEST_SHA = '501346c62e72803ffda42e9da9c67f74d7c5b733c16947d9932c8fda917e127f'
RUN = '45775775881-1'
COMMIT = '131605a726b7a79eb926886d07bf44eb721fe450'
BUNDLE = '1d999c5d5b15eb8c7539b95eb64d2febeac14b7d3835be344712969b9b4f2bc9'
WARNING = 'WARNING: Not caching stages during query-loading, since max heap size is only 1254 MB.'
PROFILES = ('luci-app-adblock-fast', 'luci-base-cb87', 'luci-mod-status')
PHASES = ('codeql-version','install-ql-lib','install-ql-src','resolve-suite','database-init','database-index','database-finalize','success-query','success-decode','errors-query','errors-decode','default-suite-analyze')

def need(condition, message):
    if not condition:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def decode(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=unique)

def load(path):
    return decode(path.read_bytes())

def verify_inventory():
    path = HERE / 'raw-manifest.json'
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe raw manifest')
    raw = path.read_bytes()
    need(digest(raw) == MANIFEST_SHA, 'raw manifest digest differs')
    manifest = decode(raw)
    files = {}
    for subtree in ('raw', 'inputs'):
        root = HERE / subtree
        need(stat.S_ISDIR(root.lstat().st_mode), 'unsafe evidence subtree')
        for path in root.rglob('*'):
            need(not path.is_symlink(), 'symlink in retained evidence')
            if path.is_file():
                need(path.stat().st_nlink == 1, 'hardlink in retained evidence')
                files[path.relative_to(HERE).as_posix()] = digest(path.read_bytes())
            else:
                need(path.is_dir(), 'special retained evidence file')
    need(files == manifest, 'retained evidence inventory differs')

def verify_profile(profile, oracle, member_index, stage, producer, coverage, routing, success, errors, sarif, resolved, commands, summary, output):
    expected = {r['path']: r for r in oracle['files']}
    need(len(expected) == len(oracle['files']) == summary['file_count'], 'oracle paths differ')
    need(stage['ipk_sha256'] == summary['ipk_sha256'] == member_index['ipk_sha256'], 'IPK identity differs')
    observed = member_index['observed_members']
    need(len(observed) == len(expected) and {r['path']:r['sha256'] for r in observed} == {p:r['sha256'] for p,r in expected.items()}, 'member identities differ')
    modes = {'luci-app-adblock-fast': {'0644':9}, 'luci-base-cb87': {'0644':73,'0755':3}, 'luci-mod-status': {'0644':31,'0755':2}}
    need(dict(Counter(r['mode'] for r in observed)) == modes[profile] and all(r['type'] == 'file' and type(r['size']) is int and r['size'] >= 0 and r['route'] == expected[r['path']]['route'] for r in observed), 'original member mode, size or route differs')
    need({r['path']:r['sha256'] for r in stage['files']} == {p:r['sha256'] for p,r in expected.items()}, 'stage member identities differ')
    origin = '/home/runner/work/_temp/r25-current-luci-' + RUN + '/r25-package/stages/' + profile + '/'
    need(routing['input_count'] == len(expected) and routing['duplicate_input_count'] == 0, 'routing count differs')
    need(Counter(r['installed_path'] for r in routing['decisions']) == Counter(expected.keys()), 'routing paths differ')
    need(dict(Counter(r['classification'] for r in routing['decisions'])) == summary['route_counts'], 'routing counts differ')
    for row in routing['decisions']:
        path = row['installed_path']
        need(row['path'] == origin + path and all(row.get(k) == v for k,v in expected[path]['route'].items()), 'routing decision differs')
    need(Counter(r['path'] for r in coverage['files']) == Counter(expected.keys()), 'coverage paths differ')
    for row in coverage['files']:
        item = expected[row['path']]
        need(row['sha256'] == item['sha256'] and row['route'] == item['route'] and row['extraction_error_count'] == 0 and row['successful_count'] == int(item['expect_success']), 'coverage row differs')
    actual = Counter()
    for entity, message in success['#select']['tuples']:
        uri = entity['url']['uri']
        parsed = urlsplit(uri)
        path = unquote(parsed.path)
        need(parsed.scheme == 'file' and not parsed.netloc and not parsed.query and not parsed.fragment and path.startswith(origin) and Path(path).as_uri() == uri and message == '', 'success URI differs')
        actual[path[len(origin):]] += 1
    need(actual == Counter(p for p,r in expected.items() if r['expect_success']) == Counter(producer['successful_files']), 'successful file multiset differs')
    need(errors['#select']['tuples'] == producer['extraction_errors'] == [], 'extraction errors present')
    need(producer['stage_files'] == {p:r['sha256'] for p,r in expected.items()}, 'producer stage differs')
    suite_root = '/home/runner/work/_temp/r25-current-luci-' + RUN + '/r25-package/producer-runs/' + profile + '/bundle/ql/src/'
    need(resolved == [suite_root + 'm4/DirectRpcShellWord.ql', suite_root + 'diagnostics/SuccessfullyExtractedFiles.ql', suite_root + 'diagnostics/ExtractionErrors.ql'], 'resolved suite differs')
    need(sarif['version'] == '2.1.0' and len(sarif['runs']) == 1 and sarif['runs'][0]['results'] == [], 'SARIF results differ')
    run = sarif['runs'][0]
    need([x['id'] for x in run['tool']['driver']['rules']] == ['ucode/m4/direct-rpc-shell-word'] and all(x['executionSuccessful'] for x in run['invocations']), 'SARIF rule or invocation differs')
    need([r['label'] for r in commands] == list(PHASES) and all(r['exit_status'] == 0 for r in commands) and producer['commands'] == commands, 'phase commands differ')
    need(coverage['commands'] == [{k:r[k] for k in ('label','elapsed_seconds','exit_status','peak_rss_kb')} for r in commands], 'phase cost receipt differs')
    warnings = []
    for row in commands:
        label = row['label']
        need(row['stderr'] == 'output/' + label + '.stderr' and row['stdout'] == 'output/' + label + '.stdout' and row['time_report'] == 'output/' + label + '.time', 'phase log path differs')
        rss = re.search(rb'Maximum resident set size \(kbytes\):\s*(\d+)', (output / (label + '.time')).read_bytes())
        need(rss is not None and int(rss.group(1)) == row['peak_rss_kb'], 'phase peak RSS differs')
        for stream in ('stdout', 'stderr'):
            for line in (output / (label + '.' + stream)).read_text().splitlines():
                if re.search(r'^\s*(?:WARNING|ERROR|FATAL):', line, re.IGNORECASE):
                    warnings.append((label, stream, line))
    need(warnings == [(x,'stderr',WARNING) for x in ('success-query','errors-query','default-suite-analyze')], 'phase warnings differ')
    return Counter(r['classification'] for r in routing['decisions'])

def main():
    verify_inventory()
    raw = HERE / 'raw'; inputs = HERE / 'inputs'
    pre = load(raw / 'preflight.json'); rollup = load(raw / 'receipt.json')
    lock = load(inputs / 'r25-current-luci-package-lock.json'); release = load(inputs / 'r3-release-lock.json')
    need(pre['run_id'] == RUN and pre['consumer_sha'] == 'cb69c826b77c3beed4cac5a22ce20e9aab7359a7' and pre['consumer_dirty'] is False, 'preflight differs')
    need(pre['package_lock_sha256'] == digest((inputs / 'r25-current-luci-package-lock.json').read_bytes()) and pre['release_lock_sha256'] == digest((inputs / 'r3-release-lock.json').read_bytes()), 'lock digest differs')
    need(release['release']['commit'] == COMMIT and release['release']['manifest_sha256'] == BUNDLE and release['release']['expected_prerelease'] is True, 'release lock differs')
    need(rollup['release_bootstrap']['release_commit'] == COMMIT and rollup['release_bootstrap']['bundle_manifest_sha256'] == BUNDLE, 'release receipt differs')
    bundle_check = load(raw / 'commands/verify-extract-bundle.stdout')
    need(bundle_check['file_count'] == 320 and bundle_check['manifest_sha256'] == BUNDLE and bundle_check['producer_commit'] == COMMIT and bundle_check['artifact_kind'] == 'versioned-release', 'bundle verification differs')
    need(all(row['exit'] == 0 for row in load(raw / 'commands.json')), 'bootstrap command failed')
    api = load(raw / 'commands/release-api.stdout')
    need(api['tag_name'] == 'v0.1.0-rc.1' and api['immutable'] is True and api['prerelease'] is True, 'release API identity differs')
    need(load(raw / 'commands/release-immutability.stdout')['isImmutable'] is True, 'release immutability differs')
    handoff = load(raw / 'r25-package/receipt.json'); need(rollup['handoff'] == handoff, 'consumer handoff differs')
    lane_commands = load(raw / 'r25-package/commands.json')
    need(handoff['commands'] == lane_commands and all(row['exit_status'] == 0 for row in lane_commands), 'consumer lane command receipt differs')
    index = load(inputs / 'member-inventory.json')['packages']
    need(digest((inputs / 'member-inventory.json').read_bytes()) == lock['member_inventory']['sha256'], 'member inventory digest differs')
    preservation = load(raw / 'r25-package/stage-preservation.json')['packages']
    need(preservation == rollup['stage_preservation'], 'stage preservation receipt differs')
    total_warnings = 0
    for profile in PROFILES:
        info = lock['packages'][profile]
        oracle_file = inputs / Path(info['oracle']['path']).name
        need(digest(oracle_file.read_bytes()) == info['oracle']['sha256'], 'source oracle digest differs')
        stage = load(raw / 'r25-package/stage-receipts' / (profile + '.json'))
        base = raw / 'r25-package/producer-runs' / profile; output = base / 'output'
        producer = load(base / 'receipt.json'); coverage = load(output / 'coverage-manifest.json')
        need(producer['producer_commit'] == coverage['producer_commit'] == COMMIT and producer['bundle_manifest_sha256'] == coverage['bundle_manifest_sha256'] == BUNDLE and producer['release_tag'] == coverage['release_tag'] == 'v0.1.0-rc.1', 'producer pin differs')
        summary = handoff['packages'][profile]
        expected_control = {'Package':info['package']['name'], 'Version':info['package']['version'], 'Architecture':info['package']['architecture']}
        need(stage['package'] == expected_control and stage['source_revisions'] == info['source_revisions'], 'stage source or control identity differs')
        need(digest((raw / 'r25-package/stage-receipts' / (profile + '.json')).read_bytes()) == summary['stage_receipt_sha256'], 'stage receipt digest differs')
        need(digest((base / 'receipt.json').read_bytes()) == summary['producer_receipt_sha256'], 'producer receipt digest differs')
        for filename, key in (('coverage-manifest.json','coverage_manifest_sha256'),('routing.json','routing_sha256'),('default-suite.sarif','sarif_sha256')):
            need(digest((output / filename).read_bytes()) == summary[key], 'consumer output digest differs: ' + filename)
        need(preservation[profile]['analysis_stage_sha256_by_path'] == producer['stage_files'] and set(preservation[profile]['analysis_stage_mode_by_path']) == set(producer['stage_files']) and set(preservation[profile]['analysis_stage_mode_by_path'].values()) == {'0600'}, 'private stage preservation differs')
        need(load(output / 'resolved-suite.json') == rollup['raw_producer_output_audit'][profile]['resolved_query_paths'], 'consumer resolved suite differs')
        verify_profile(profile, load(oracle_file), index[info['package']['name']], stage, producer, coverage, load(output / 'routing.json'), load(output / 'success.json'), load(output / 'errors.json'), load(output / 'default-suite.sarif'), load(output / 'resolved-suite.json'), load(base / 'commands.json'), summary, output)
        total_warnings += 3
    need(total_warnings == 9, 'warning count differs')
    need('etc/luci-uploads/.placeholder' in rollup['stage_preservation']['luci-base-cb87']['hidden_paths'], 'hidden stage path absent')
    print('three released package receipts consistent; 9 reviewed performance warnings')

if __name__ == '__main__':
    main()
