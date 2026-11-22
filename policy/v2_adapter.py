"""Opt-in, read-only v2 boundary for bounded assessment experiments.

The caller independently selects the context, scope, pairs and input digests.
Hashes bind bytes to that selection; they do not authenticate their origin.
This module does not write files and does not select a policy from an artifact.
"""
import hashlib
import re

from .v2_json import parse_json
from .v2_resolver import ResolutionError, resolve, validate_context
from .setblock_table import same_json

_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
_PACKAGE = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.+-]+@sha256:[0-9a-f]{64}\Z')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def assess_status(*, selection, envelope_raw, policy_raw, fixture_raw, corpus_raw, profile_raw,
                  caller_package_raw, provider_package_raw, caller_content_raw, provider_content_raw,
                  permission_raw=None, resource_raw=None):
    """Evaluate an independently selected synthetic status fixture.

    ``selection`` is the trusted selection supplied out of band, not parsed
    from the envelope. It has exactly context, scope and pairs. Context policy
    and input values are independently selected SHA-256 digests. Corpus and
    profile bytes are separately supplied and bound to their selected identities. The policy bytes are an authority-to-definitions map.
    Fixture bytes contain the question; independently bound permission and
    resource records establish the synthetic conjunction. Package manifests
    bind the separately supplied synthetic content. These are fixture facts,
    not claims about a real provider or authenticated package provenance.
    """
    if not isinstance(selection, dict) or set(selection) != {'context', 'scope', 'pairs'}:
        raise ResolutionError('invalid selection')
    context = selection['context']
    if (not isinstance(context, dict) or set(context) != {'corpus', 'profile', 'policy', 'inputs'}
            or any(not isinstance(context[k], str) or not _DIGEST.fullmatch(context[k])
                   for k in ('corpus', 'profile', 'policy'))
            or not isinstance(context['inputs'], dict)
            or set(context['inputs']) != {'status-fixture', 'caller-package', 'provider-package', 'permission', 'resource'}
            or any(not isinstance(v, str) or not _DIGEST.fullmatch(v) for v in context['inputs'].values())):
        raise ResolutionError('invalid selected context')
    scope = selection['scope']
    if (not isinstance(scope, dict) or set(scope) != {'caller', 'profile', 'ingress', 'entrypoint', 'packages'}
            or any(not isinstance(scope[k], str) or not scope[k].strip()
                   or scope[k].strip() != scope[k] or scope[k].lower() in {'unknown', 'none', 'unspecified'}
                   for k in ('caller', 'ingress', 'entrypoint'))
            or scope['caller'] != 'status-client' or scope['ingress'] != 'fixture-transport'
            or scope['entrypoint'] != 'status.read'
            or not isinstance(selection['pairs'], list)
            or {'target': 'status', 'operation': 'read'} not in selection['pairs']
            or any(not any(same_json(pair, supported) for supported in (
                {'target': 'status', 'operation': 'read'},
                {'target': 'status-metadata', 'operation': 'inspect'})) for pair in selection['pairs'])
            or scope['profile'] != context['profile']
            or not isinstance(scope['packages'], dict)
            or set(scope['packages']) != {'caller', 'provider'}
            or any(not isinstance(v, str) or not _PACKAGE.fullmatch(v) for v in scope['packages'].values())
            or scope['packages']['caller'].split('@', 1)[0] == scope['packages']['provider'].split('@', 1)[0]
            or any('unknown' in v.lower().split('@')[0].split('/') for v in scope['packages'].values())
            or any(scope['packages'][k].split('@', 1)[1] != context['inputs'][k + '-package']
                   for k in ('caller', 'provider'))):
        raise ResolutionError('invalid selected scope')
    if (_digest(policy_raw) != context['policy']
            or _digest(fixture_raw) != context['inputs']['status-fixture']
            or _digest(corpus_raw) != context['corpus'] or _digest(profile_raw) != context['profile']
            or _digest(caller_package_raw) != context['inputs']['caller-package']
            or _digest(provider_package_raw) != context['inputs']['provider-package']):
        raise ResolutionError('selected byte identity mismatch')
    for role, manifest_raw, content_raw in (
            ('caller', caller_package_raw, caller_content_raw),
            ('provider', provider_package_raw, provider_content_raw)):
        manifest = parse_json(manifest_raw)
        identity = scope['packages'][role]
        feed, name, version = identity.split('@', 1)[0].split('/')
        expected = {'role': role, 'feed': feed, 'name': name, 'version': version,
                    'content_sha256': _digest(content_raw)}
        if not same_json(manifest, expected):
            raise ResolutionError('package manifest identity mismatch')
    for key, value in (('permission', permission_raw), ('resource', resource_raw)):
        if value is not None and _digest(value) != context['inputs'][key]:
            raise ResolutionError('selected byte identity mismatch')
    envelope = parse_json(envelope_raw)
    if not isinstance(envelope, dict) or set(envelope) != {'kind', 'version', 'context', 'reference', 'verdict'}:
        raise ResolutionError('invalid v2 envelope')
    validate_context(context, {k: envelope[k] for k in ('kind', 'version', 'context')})
    policies = parse_json(policy_raw)
    fixture = parse_json(fixture_raw)
    if (not isinstance(fixture, dict) or set(fixture) != {'scope', 'pairs'}
            or not same_json(fixture['scope'], scope) or not same_json(fixture['pairs'], selection['pairs'])):
        raise ResolutionError('fixture identity mismatch')
    permission = None if permission_raw is None else parse_json(permission_raw)
    resource = None if resource_raw is None else parse_json(resource_raw)
    expected_permission = {'caller': scope['caller'], 'package': scope['packages']['caller'],
                           'ingress': scope['ingress'], 'entrypoint': scope['entrypoint'],
                           'corpus': context['corpus'], 'profile': context['profile'],
                           'provider': scope['packages']['provider'], 'target': 'status',
                           'operation': 'read', 'pairs': selection['pairs'], 'allowed': True}
    expected_resource = {'package': scope['packages']['provider'], 'target': 'status',
                         'operation': 'read', 'pairs': selection['pairs'], 'corpus': context['corpus'],
                         'profile': context['profile'], 'available': True}
    # Validate policy and any asserted reference even when gate evidence is absent.
    policy = resolve(scope=scope, pairs=selection['pairs'], authorities=policies,
                     reference=envelope['reference'], verdict=envelope['verdict'])
    gate = ('allow' if same_json(permission, expected_permission)
            and same_json(resource, expected_resource) else 'unknown')
    if gate == 'allow' and policy['status'] == 'matched':
        policy = dict(policy, status='assessed')
    elif gate != 'allow' and policy['status'] != 'conflict':
        policy = {'status': 'unassessed'}
    return {'gate': gate, 'policy': policy}


def main(argv=None):
    """Read explicitly selected files and print the bounded result to stdout."""
    import argparse
    import json
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('status', 'setblock'), required=True)
    for name in ('selection', 'envelope', 'policy', 'corpus', 'profile'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--caller-package', type=Path)
    parser.add_argument('--provider-package', type=Path)
    parser.add_argument('--caller-content', type=Path)
    parser.add_argument('--provider-content', type=Path)
    parser.add_argument('--permission', type=Path)
    parser.add_argument('--resource', type=Path)
    parser.add_argument('--evidence', action='append', default=[], metavar='NAME=PATH')
    args = parser.parse_args(argv)
    try:
        common = dict(selection=parse_json(args.selection.read_bytes()),
                      envelope_raw=args.envelope.read_bytes(), policy_raw=args.policy.read_bytes(),
                      corpus_raw=args.corpus.read_bytes(), profile_raw=args.profile.read_bytes())
        if args.family == 'status':
            if args.fixture is None or args.caller_package is None or args.provider_package is None or args.caller_content is None or args.provider_content is None or args.evidence:
                raise ValueError('status requires --fixture and no --evidence')
            result = assess_status(**common, fixture_raw=args.fixture.read_bytes(),
                                   caller_package_raw=args.caller_package.read_bytes(),
                                   provider_package_raw=args.provider_package.read_bytes(),
                                   caller_content_raw=args.caller_content.read_bytes(),
                                   provider_content_raw=args.provider_content.read_bytes(),
                                   permission_raw=args.permission.read_bytes() if args.permission else None,
                                   resource_raw=args.resource.read_bytes() if args.resource else None)
        else:
            if any((args.fixture, args.caller_package, args.provider_package, args.caller_content,
                    args.provider_content, args.permission, args.resource)):
                raise ValueError('setblock does not accept --fixture')
            evidence = {}
            for item in args.evidence:
                name, separator, path = item.partition('=')
                if not separator or not name or not path or name in evidence:
                    raise ValueError('invalid or duplicate evidence argument')
                evidence[name] = Path(path).read_bytes()
            result = assess_setblock(**common, inputs=evidence)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


# Historical bytes are consistency pins for the reviewed archived handoff, not
# authentication of the producer or proof of runtime registration.
_REAL_INPUTS = {
    'typed': 'sha256:5c619d5aa3566c5296080b0a9be7072b38d6eb7a98eae647d68c5dcf09b2b59b',
    'recipe-system': 'sha256:315224a6aed5598eb229533eb73cc846e79f9d1f6fba4d1e75587910ef95cfe7',
    'recipe-base': 'sha256:4a933ee77787783219bdeae45b03d89a6c3b5f1512e8ad8bc68d19f4b250c9bc',
    'recipe-ssl': 'sha256:a02dc41d525f1a0f0cbdb5b697a66bcc3b371b0f25a6362d0d2bc5fd8cf3f684',
    'recipe-light': 'sha256:1d02f3bad127162339bcc49524c383a18c336f9ff832b391fa499184e974fbc6',
    'recipe-admin': 'sha256:c64544d6700cc3068b8708f84b66dfdcdc2f49730cc99aae2d3c75fbdd130205',
    'uhttpd-recipe': 'sha256:5d8b66c3f0ad09f3f43507f9025c778bace19b94c77d306d782128593f8feac6',
    'uhttpd-default': 'sha256:4cae1c943a1efc41449c377db3e2b5338b36cbcb815f388fea6d86c972b3927d',
    'uhttpd-config': 'sha256:6cc793366729d4792b95139780baa4fbfc3402db6b63aa015d3007b34510e14a',
    'uhttpd-init': 'sha256:49af2183baad478567bb74d484396142909959b4653ece0379e8dd159b19070e',
    'feed-config': 'sha256:0843b89011b0264ca1a21140bbfa039436080134c6f84c76a7a1c936f8ce3db0',
    'source-archive': 'sha256:c3a841f0f08290af2c73624d376008f109de5a39211e42ae48ac3c5e173d5ab8',
    'source': 'sha256:6f9d972958d9cfb8a7ba421f38f0a5b03718ffeb0e30d460b64c9faf725fc54e',
    'errors': 'sha256:0bb9068729a2970f4b125b6893565812fdd2d1fc6510626f214f3d055b4f94f5',
    'extracted': 'sha256:ab842728312739e69fc47983c85abaa09a59a297ead156d6ceca3df333b570f4',
    'effects': 'sha256:9d9a1a7178e7f5fbd3cb772122fe172354004fac09ce00e91647d6b35ba9d0a0',
    'routing': 'sha256:6b966b0d86873d3edc0602d7558e5bef74796edf60a74d3ad423f636cc5c47d6',
    'login': 'sha256:87870ce2884e31bddf9744b6bbe201e11b5f62991dc2169f6afe810372cd8ac2',
    'acl': 'sha256:16a24f388ca457758afbea4ff2283ad5984b0146d01697a6955ea84f42cb7924',
}
_REAL_PACKAGES = {
    'caller': 'luci/luci-mod-system/b2e0be4b46ec0fd43394c081fa7c50657af14011@' + _REAL_INPUTS['acl'],
    'provider': 'luci/luci-base/b2e0be4b46ec0fd43394c081fa7c50657af14011@' + _REAL_INPUTS['source'],
}
_ARCHIVE_SOURCE = ('/root/workspace/workflow-design/evidence/issue89-typed-ae946190-7f532ac-a3/'
                   'sealed/ql/test/extractor-smoke/usr/share/rpcd/ucode/luci')
_REAL_POLICY = 'sha256:8192803552814c47cb39b99712c033d0aa5a6631a6d32e05315bd9666630881c'
_REAL_AUTHORITY = 'openwrt-consumer:luci-ssl-25.12'
_REAL_PROFILE = 'sha256:16a5468601be4b23f45795a43deedd6fda6726ff7503abb9d80e493d16808ac5'
_REAL_CORPUS = 'sha256:b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a'



def _validate_source_archive(archive, source):
    """Require the single reviewed installed-source archive member."""
    import io
    import stat
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            members = z.infolist()
            if (len(members) != 1 or members[0].filename != _ARCHIVE_SOURCE.lstrip('/')
                    or members[0].is_dir() or members[0].create_system != 3
                    or not stat.S_ISREG(members[0].external_attr >> 16)
                    or z.read(members[0]) != source):
                raise ResolutionError('unexpected archived source inventory')
    except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise ResolutionError('invalid source archive') from exc


def _validate_archive(inputs):
    """Check the decoded retained rows independently of their byte pins."""
    import csv
    import io
    from . import setblock_table

    def rows(name):
        try:
            return list(csv.reader(io.StringIO(inputs[name].decode('utf-8'), newline=''), strict=True))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ResolutionError('invalid archived CSV') from exc

    if rows('effects') != [list(setblock_table.COLUMNS), list(setblock_table.EXPECTED)]:
        raise ResolutionError('unexpected archived effect')
    if rows('errors') != [['error', 'col1', 'col2']]:
        raise ResolutionError('unexpected extraction diagnostics')
    extracted = rows('extracted')
    if (len(extracted) != 2 or extracted[0] != ['f', 'col1'] or len(extracted[1]) != 2
            or extracted[1][0] != _ARCHIVE_SOURCE
            or extracted[1][1] != ''):
        raise ResolutionError('unexpected extraction inventory')
    routing = parse_json(inputs['routing'])
    expected_counts = {'input_count': 1, 'plain_count': 1, 'markup_count': 0,
                       'markup_inconclusive_count': 0, 'uncertain_count': 0,
                       'excluded_count': 0, 'duplicate_input_count': 0}
    if (not isinstance(routing, dict) or set(routing) != set(expected_counts) | {'decisions'}
            or not all(same_json(routing[k], v) for k, v in expected_counts.items())
            or not isinstance(routing['decisions'], list) or len(routing['decisions']) != 1):
        raise ResolutionError('unexpected routing inventory')
    decision = routing['decisions'][0]
    if (not isinstance(decision, dict) or decision != {
            'path': extracted[1][0], 'installed_path': setblock_table.SOURCE_PATH,
            'classification': 'plain', 'reason': 'rpcd_raw_mode_full_path',
            'status': 'plain_route_selected'}):
        raise ResolutionError('unexpected routing decision')
    lines = inputs['source'].decode('utf-8').splitlines()
    if lines[529:534] != ["\tsetBlockDetect: {", "\t\tcall: function() {",
                           "\t\t\treturn { result: system('/sbin/block detect > /etc/config/fstab') == 0 };",
                           "\t\t}", "\t},"]:
        raise ResolutionError('unexpected source command')


def _validate_source_model(inputs, profile):
    """Check the exact pinned feed and supported source dependency chain."""
    def deps(key):
        text = inputs[key].decode('utf-8').replace('\\\n', ' ')
        match = re.search(r'^LUCI_DEPENDS\s*:=([^\n]*)', text, re.MULTILINE)
        if match is None:
            raise ResolutionError('missing recipe dependencies')
        return set(re.findall(r'(?<![\w-])\+([A-Za-z0-9_-]+)', match.group(1)))

    if (profile.get('config_seed', {}).get('CONFIG_PACKAGE_luci-ssl') != 'y'
            or 'luci-light' not in deps('recipe-ssl')
            or not {'luci-mod-admin-full', 'uhttpd-mod-ubus'} <= deps('recipe-light')
            or not {'luci-base', 'luci-mod-system'} <= deps('recipe-admin')
            or 'luci-base' not in deps('recipe-system')
            or 'rpcd-mod-ucode' not in deps('recipe-base')
            or not re.search(r'^PKG_NAME:=luci-base$', inputs['recipe-base'].decode('utf-8'), re.MULTILINE)
            or '$(INSTALL_DATA) ./files/ubus.default $(1)/etc/uci-defaults/00_uhttpd_ubus'
               not in inputs['uhttpd-recipe'].decode('utf-8')
            or not re.search(r'^if \[ -z .*uci -q get uhttpd.main.ubus_prefix.*; then\n\s*uci set uhttpd.main.ubus_prefix=/ubus\nfi$',
                             inputs['uhttpd-default'].decode('utf-8'), re.MULTILINE)
            or not re.search(r'^\s*#\s*option ubus_prefix\s+/ubus$', inputs['uhttpd-config'].decode('utf-8'), re.MULTILINE)
            or not re.search(r'^\s*\[ -f /usr/lib/uhttpd_ubus\.so \] && \{\n\s*append_arg "\$cfg" ubus_prefix "-u"$',
                             inputs['uhttpd-init'].decode('utf-8'), re.MULTILINE)
            or 'src-git luci https://git.openwrt.org/project/luci.git;openwrt-25.12'
               not in inputs['feed-config'].decode('utf-8').splitlines()):
        raise ResolutionError('unsupported source dependency model')


def _project_real_policy(raw, scope, pairs):
    """Validate the selected original registry before its reviewed narrowing."""
    registry = parse_json(raw)
    if (not isinstance(registry, dict) or registry.get('profile') != 'luci-ssl-25.12'
            or not isinstance(registry.get('expectations'), list)):
        raise ResolutionError('invalid selected registry')
    entries = registry['expectations']
    ids = [entry.get('expectation_id') if isinstance(entry, dict) else None for entry in entries]
    if (any(not isinstance(i, str) or not i or i.strip() != i for i in ids)
            or len(ids) != len(set(ids))):
        raise ResolutionError('invalid or duplicate registry ID')
    entry = entries[ids.index('luci-mod-system-mounts')] if 'luci-mod-system-mounts' in ids else None
    if (not isinstance(entry, dict) or entry.get('session_class') != 'luci-mod-system-mounts'
            or entry.get('synthetic') is not True or entry.get('ingress') != 'ubus_http'
            or 'entrypoint_id' in entry
            or {'target_id': 'ubus:luci.setBlockDetect', 'op': 'invoke'} not in entry.get('intended_access', [])
            or not any(isinstance(helper, dict) and helper.get('sink_kind') == 'system'
                       and helper.get('constraint') == 'fixed_command'
                       and isinstance(helper.get('examples'), list)
                       and '/sbin/block detect > /etc/config/fstab' in helper['examples']
                       for helper in entry.get('allowed_helper_effects', []))):
        raise ResolutionError('unsupported selected registry definition')
    return {_REAL_AUTHORITY: [{'id': 'luci-mod-system-mounts', 'scope': scope, 'pairs': pairs}]}

def assess_setblock(*, selection, envelope_raw, policy_raw, corpus_raw, profile_raw, inputs):
    """Assess the historical observation against the selected bounded policy.

    ``inputs`` maps the names in ``_REAL_INPUTS`` to their raw bytes. Missing
    evidence is unknown. A Linux modeled gate allow is source-level only;
    hashes bind bytes but do not authenticate provenance.
    """
    from . import oracle, setblock_table
    import sys

    if not isinstance(selection, dict) or set(selection) != {'context', 'scope', 'pairs'}:
        raise ResolutionError('invalid selection')
    context, scope = selection['context'], selection['scope']
    if (not isinstance(context, dict) or set(context) != {'corpus', 'profile', 'policy', 'inputs'}
            or context['corpus'] != _REAL_CORPUS or context['inputs'] != _REAL_INPUTS
            or not isinstance(context['policy'], str) or not _DIGEST.fullmatch(context['policy'])
            or context['profile'] != _REAL_PROFILE):
        raise ResolutionError('invalid selected context')
    if (_digest(corpus_raw) != context['corpus'] or _digest(profile_raw) != context['profile']
            or _digest(policy_raw) != context['policy']):
        raise ResolutionError('selected byte identity mismatch')
    lock = parse_json(corpus_raw)
    if (lock.get('repos', {}).get('luci', {}).get('sha') != oracle.LUCI_SHA
            or lock.get('packages', {}).get('uhttpd', {}).get('PKG_SOURCE_VERSION') != oracle.UHTTPD_SHA
            or lock.get('packages', {}).get('rpcd', {}).get('PKG_SOURCE_VERSION') != oracle.RPCD_SHA):
        raise ResolutionError('unsupported gate revisions')
    profile = parse_json(profile_raw)
    if (profile.get('profile') != 'luci-ssl-25.12'
            or not same_json(profile.get('uhttpd', {}).get('no_ubusauth'), 0)):
        raise ResolutionError('unsupported profile')
    if (not isinstance(scope, dict) or set(scope) != {'caller', 'profile', 'ingress', 'entrypoint', 'packages'}
            or scope['caller'] != 'luci-mod-system-mounts' or scope['profile'] != context['profile']
            or scope['ingress'] != 'ubus_http' or scope['entrypoint'] != 'ubus_http:luci.setBlockDetect'
            or scope['packages'] != _REAL_PACKAGES
            or selection['pairs'] != [{'target': 'ubus:luci.setBlockDetect', 'operation': 'invoke'}]):
        raise ResolutionError('unsupported real scope')
    envelope = parse_json(envelope_raw)
    if not isinstance(envelope, dict) or set(envelope) != {'kind', 'version', 'context', 'reference', 'verdict'}:
        raise ResolutionError('invalid v2 envelope')
    validate_context(context, {k: envelope[k] for k in ('kind', 'version', 'context')})
    assessed = envelope['reference'] is not None or envelope['verdict'] is not None
    if assessed:
        if context['policy'] != _REAL_POLICY:
            raise ResolutionError('unsupported real assessed policy')
        authorities = _project_real_policy(policy_raw, scope, selection['pairs'])
    else:
        authorities = (_project_real_policy(policy_raw, scope, selection['pairs'])
                       if context['policy'] == _REAL_POLICY else parse_json(policy_raw))
    policy = resolve(scope=scope, pairs=selection['pairs'], authorities=authorities,
                     reference=envelope['reference'], verdict=envelope['verdict'])
    if not isinstance(inputs, dict) or set(inputs) - set(_REAL_INPUTS):
        raise ResolutionError('invalid evidence inputs')
    if any(not isinstance(v, bytes) or _digest(v) != _REAL_INPUTS[k] for k, v in inputs.items()):
        raise ResolutionError('evidence byte identity mismatch')
    result = {'gate': 'unknown', 'policy': policy, 'observation': 'unknown', 'modeled_gate': 'unknown',
              'limits': ['allow describes the pinned source model, not a built or installed package',
                         'selected policy is a bounded consumer expectation, not authenticated provenance',
                         'model assumes the ubus default script ran with no prior prefix and the plugin is present',
                         'modeled object lookup assumes luci exists; live registration is not established',
                         'archived evidence does not establish live execution',
                         'ucode string-form system uses a shell; the fixed command includes redirection']}
    if set(inputs) != set(_REAL_INPUTS):
        if policy['status'] == 'matched':
            result['policy'] = {'status': 'unassessed'}
        return result
    _validate_source_model(inputs, profile)
    _validate_source_archive(inputs['source-archive'], inputs['source'])
    _validate_archive(inputs)
    typed = parse_json(inputs['typed'])
    setblock_table.validate_typed_records(typed, inputs['source'], lock, context['corpus'])
    result['typed_unknowns'] = list(typed[0]['unknowns'])
    result['typed_assumptions'] = list(typed[0]['assumptions'])
    result['observation'] = 'archived-neutral-observation'
    if sys.platform != 'linux':
        result['limits'].append('Linux libc evaluator unavailable on this platform')
        if policy['status'] == 'matched':
            result['policy'] = {'status': 'unassessed'}
        return result
    logins = {x.username: x for x in oracle.parse_rpcd_logins(inputs['login'].decode('utf-8'))}
    acl = parse_json(inputs['acl'])
    entries = []
    for group, body in acl.items():
        for perm in ('read', 'write'):
            for scope_name, scope_value in body.get(perm, {}).items():
                entries.extend(oracle._iter_scope_grants(group, perm, scope_name, scope_value, 'luci-mod-system.json'))
    login = logins['luci-mod-system-mounts']
    session = oracle.Session(session_class='luci-mod-system-mounts', sid=oracle.MOUNTS_FIXTURE_SID,
                             login=login, acls=oracle.session_acls(login, entries))
    evaluated = oracle.evaluate_call(session_class='luci-mod-system-mounts', sid=oracle.MOUNTS_FIXTURE_SID,
                                     object='luci', function='setBlockDetect', data={}, no_ubusauth=0,
                                     sessions={oracle.MOUNTS_FIXTURE_SID: session}, object_exists=True)
    if (evaluated.outcome == 'allow' and evaluated.matched is not None
            and evaluated.matched.group == 'luci-mod-system-mounts'
            and evaluated.matched.perm == 'write' and evaluated.matched.object == 'luci'
            and evaluated.matched.function == 'setBlockDetect'):
        result['modeled_gate'] = 'allow'
        result['gate'] = 'allow'
        if policy['status'] == 'matched':
            result['policy'] = dict(policy, status='assessed')
    if result['policy']['status'] == 'matched':
        result['policy'] = {'status': 'unassessed'}
    return result


if __name__ == '__main__':
    raise SystemExit(main())
