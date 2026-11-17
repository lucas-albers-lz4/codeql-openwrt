"""Synthetic CSV controls only: these are not a producer execution or handoff."""
import copy
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from policy import setlocaltime_construction as c

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT/'policy/fixtures/getblock-source'
SOURCE = SOURCE_ROOT/c.SOURCE_PATH
ORACLE = json.loads((ROOT/c.ORACLE_PATH).read_bytes())


def csv_bytes(rows):
    stream = io.StringIO(newline='')
    csv.writer(stream, lineterminator='\n').writerows(rows)
    return stream.getvalue().encode('utf-8')


def synthetic_rows():
    # Construct controls from a consumer source oracle, not actual producer output.
    o = ORACLE['observation']
    common = [o['observation_kind'], 'luci', 'setLocaltime', c.SOURCE_PATH, 't', o['format_value']]
    for k in ('callback','initializer','input','guard','formatter','format','sink'):
        common += o[k]
    return [c.HEADER] + [common + [s['slot_index'], s['conversion'], s['field_name']] + s['field'] for s in o['slots']]


def diagnostics(root=SOURCE_ROOT):
    return (csv_bytes([['f','col1'], [str(root/c.SOURCE_PATH),'']]), csv_bytes([['error','col1','col2']]))


def protected():
    return {str(p.relative_to(ROOT)):(p.stat().st_mode, p.read_bytes()) for base in ('policy','corpus','reports') for p in (ROOT/base).rglob('*') if p.is_file() and p.suffix != '.pyc' and '__pycache__' not in p.parts}


def inventory(root):
    # Include paths, modes, symlink targets and file contents, not just files
    # already expected to exist. The consumer must not create artifacts.
    result = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        if Path(current) == root:
            dirs[:] = [name for name in dirs if name != '.git']
            files = [name for name in files if name != '.git']
        for name in dirs + files:
            p = Path(current)/name
            mode = p.lstat().st_mode
            result[str(p.relative_to(root))] = (mode, os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
    return result


class TableTests(unittest.TestCase):
    def test_missing_table_is_unassessed(self):
        with self.assertRaises(c.ValidationError): c.parse_table(b'')

    def test_source_oracle_anchors_are_actual_pinned_bytes(self):
        data = SOURCE.read_bytes()
        self.assertEqual(c.digest(data), ORACLE['source_sha256'])
        lines = data.splitlines()
        def text(span):
            a,b,x,y = span
            if a == x: return lines[a-1][b-1:y].decode()
            return b'\n'.join([lines[a-1][b-1:]] + lines[a:x-1] + [lines[x-1][:y]]).decode()
        o = ORACLE['observation']
        self.assertTrue(text(o['callback']).startswith('function(request) {'))
        self.assertTrue(text(o['callback']).endswith('}'))
        self.assertEqual(text(o['initializer']), 'localtime(request.args.localtime)')
        self.assertEqual(text(o['input']), 'request.args.localtime')
        self.assertEqual(text(o['guard']), 't')
        self.assertEqual(text(o['format']), "'"+o['format_value']+"'")
        self.assertEqual(text(o['formatter']), 'sprintf('+text(o['format'])+', t.year, t.mon, t.mday, t.hour, t.min, t.sec)')
        self.assertEqual(text(o['sink']), 'system('+text(o['formatter'])+')')
        self.assertIn("system('/etc/init.d/sysfixtime restart", lines[111].decode())
        for slot in o['slots']:
            self.assertEqual(text(slot['field']), 't.'+slot['field_name'])
        self.assertEqual([s['conversion'] for s in o['slots']], ['%04d']+['%02d']*5)
        self.assertEqual([s['field_name'] for s in o['slots']], ['year','mon','mday','hour','min','sec'])

    def test_composed_valid_and_order_independent(self):
        ex, err = diagnostics(); rows = synthetic_rows()
        result = c.compare(csv_bytes(rows), ex, err, str(SOURCE_ROOT))
        reverse = c.compare(csv_bytes(rows[:1]+list(reversed(rows[1:]))), ex, err, str(SOURCE_ROOT))
        self.assertEqual(result['observation'], ORACLE['observation'])
        self.assertEqual(result['observation'], reverse['observation'])
        self.assertIs(result['execution_verified'], False)
        self.assertEqual(result['validation_scope'], 'exact_pinned_source_construction_only')
        self.assertEqual(result['unknowns'], c.UNKNOWN)
        self.assertEqual(result['links']['primary_grant_ids'], [c.PRIMARY])
        self.assertEqual(result['links']['supplementary_grant_ids'], [c.SUPPLEMENTARY])
        self.assertIn('t.year', c.render_markdown(result))
        self.assertIn('dynamic global mutation', c.render_markdown(result))

    def test_table_falsifications_through_api_and_cli(self):
        rows = synthetic_rows()
        variants = {'empty': b'', 'missing': csv_bytes(rows[:-1]), 'duplicate': csv_bytes(rows + [rows[-1]]),
                    'same-count-duplicate': csv_bytes(rows[:-1]+[rows[-2]]), 'bom': b'\xef\xbb\xbf'+csv_bytes(rows),
                    'malformed': csv_bytes(rows)+b'"unterminated', 'extra-column': csv_bytes([r+[''] for r in rows])}
        for name, column, value in [('slot',34,2), ('field',36,'mon'), ('conversion',35,'%s'), ('sibling',30,112), ('span',7,10), ('boolean',34,'true'), ('float',7,'107.0'), ('leading-zero',7,'09'), ('method',2,'other'), ('path',3,'other')]:
            r = copy.deepcopy(rows); r[1][column] = value; variants[name] = csv_bytes(r)
        r = copy.deepcopy(rows); r[1][36], r[2][36] = r[2][36], r[1][36]; variants['identity-swap'] = csv_bytes(r)
        # Permissive csv.reader accepts this quote tail, strict=True must not.
        variants['quote-tail'] = csv_bytes(rows).replace(b'"date -s ', b'"date -s ', 1).replace(b'111,74,111,79', b'111,74,111,79"', 1)
        ex, err = diagnostics(); before = protected()
        with tempfile.TemporaryDirectory() as tmp:
            t,e,x = [Path(tmp)/n for n in ('table','extracted','errors')]
            e.write_bytes(ex); x.write_bytes(err)
            cmd = [sys.executable,'-B'] + (['-O'] if sys.flags.optimize else []) + ['-m','policy.setlocaltime_construction','--table',str(t),'--extracted',str(e),'--errors',str(x),'--source-root',str(SOURCE_ROOT)]
            for name, blob in variants.items():
                with self.subTest(name=name):
                    with self.assertRaises(c.ValidationError): c.compare(blob, ex, err, str(SOURCE_ROOT))
                    t.write_bytes(blob); result = subprocess.run(cmd,cwd=ROOT,capture_output=True)
                    self.assertNotEqual(result.returncode, 0, name)
                    self.assertEqual(result.stdout, b'')
        self.assertEqual(before, protected())

    def test_strict_parser_rejects_quote_tail_before_identity_check(self):
        blob = csv_bytes(synthetic_rows()).replace(b',luci,setLocaltime,', b',"luci"x,setLocaltime,', 1)
        self.assertNotEqual(list(csv.reader(io.StringIO(blob.decode())))[1][1], 'luci')
        with self.assertRaises(c.ValidationError): c.parse_table(blob)

    def test_unquoted_embedded_quotes_rejected(self):
        # Python csv strict=True otherwise accepts a quote in an unquoted field.
        blob = csv_bytes(synthetic_rows()).replace(b',luci,setLocaltime,', b',lu"ci,setLocaltime,', 1)
        with self.assertRaises(c.ValidationError): c.parse_table(blob)

    def test_every_coordinate_endpoint_is_exact(self):
        table = synthetic_rows(); ex, err = diagnostics()
        for column in list(range(6,34)) + list(range(37,41)):
            changed = copy.deepcopy(table); changed[1][column] = str(int(changed[1][column]) + 1)
            with self.subTest(column=column), self.assertRaises(c.ValidationError):
                c.compare(csv_bytes(changed),ex,err,str(SOURCE_ROOT))

    def test_diagnostics_and_source_alias_fail_closed(self):
        table = csv_bytes(synthetic_rows()); ex, err = diagnostics()
        for x,e in [(b'',err),(csv_bytes([['f','col1']]),err),(ex+ex.splitlines(keepends=True)[1],err),(ex,b''),(ex,err+b'error,x,x\n'),(b'"f"x,col1\n',err)]:
            with self.subTest(x=x,e=e), self.assertRaises(c.ValidationError): c.compare(table,x,e,str(SOURCE_ROOT))
        with self.assertRaises(c.ValidationError): c.compare(table,ex,err,str(SOURCE_ROOT)+'/../getblock-source')
        with tempfile.TemporaryDirectory() as d:
            alias = Path(d)/'alias'; alias.symlink_to(SOURCE_ROOT, target_is_directory=True)
            with self.assertRaises(c.ValidationError): c.compare(table,ex,err,str(alias))

    def test_source_bytes_changed_but_declared_hash_is_original(self):
        self._check_source_file_guard('changed-bytes')

    def test_source_file_alias_under_canonical_root(self):
        self._check_source_file_guard('file-alias')

    def _check_source_file_guard(self, variant):
        # Both negatives have otherwise valid synthetic table/diagnostics. A
        # positive control in the same canonical root proves the rest of the
        # composed API and real CLI paths are capable of accepting the input.
        table = csv_bytes(synthetic_rows())
        with tempfile.TemporaryDirectory() as d:
            work = Path(d).resolve()
            root = work/'source-root'
            source = root/c.SOURCE_PATH
            source.parent.mkdir(parents=True)
            original = SOURCE.read_bytes()
            self.assertEqual(c.digest(original), ORACLE['source_sha256'])
            self.assertEqual(c.digest(original), c.SOURCE_HASH)
            source.write_bytes(original)
            self.assertEqual(root.resolve(), root)
            ex, err = diagnostics(root)
            t,e,x = [work/n for n in ('table','extracted','errors')]
            t.write_bytes(table); e.write_bytes(ex); x.write_bytes(err)
            cmd = [sys.executable,'-B'] + (['-O'] if sys.flags.optimize else []) + ['-m','policy.setlocaltime_construction','--table',str(t),'--extracted',str(e),'--errors',str(x),'--source-root',str(root)]
            before_repo = inventory(ROOT)
            before_valid = inventory(work)
            report = c.compare(table, ex, err, str(root))
            self.assertEqual(report['source']['sha256'], c.SOURCE_HASH)
            self.assertEqual(report['observation'], ORACLE['observation'])
            valid = subprocess.run(cmd, cwd=ROOT, capture_output=True)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(json.loads(valid.stdout)['source']['sha256'], c.SOURCE_HASH)
            self.assertEqual(valid.stderr, b'')
            self.assertEqual(inventory(work), before_valid)
            self.assertEqual(inventory(ROOT), before_repo)

            if variant == 'changed-bytes':
                source.write_bytes(original+b'\n')
                self.assertEqual(source.resolve(), source)
                self.assertNotEqual(c.digest(source.read_bytes()), c.SOURCE_HASH)
            else:
                target = source.with_name('luci-real')
                source.rename(target)
                source.symlink_to(target.name)
                self.assertNotEqual(source.resolve(), source)
                self.assertEqual(c.digest(source.read_bytes()), c.SOURCE_HASH)
            before_invalid = inventory(work)
            with self.subTest(path='API'):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    with self.assertRaisesRegex(c.ValidationError, '^source path or digest mismatch$'):
                        c.compare(table, ex, err, str(root))
                self.assertEqual(stdout.getvalue(), '')
            with self.subTest(path='CLI'):
                result = subprocess.run(cmd, cwd=ROOT, capture_output=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'unassessed: source path or digest mismatch\n')
            self.assertEqual(inventory(work), before_invalid)
            self.assertEqual(inventory(ROOT), before_repo)

    def test_invalid_diagnostics_cli_no_payload(self):
        table = csv_bytes(synthetic_rows()); ex, err = diagnostics(); before = protected()
        with tempfile.TemporaryDirectory() as d:
            t,e,x = [Path(d)/n for n in ('table','extracted','errors')]
            t.write_bytes(table)
            cmd = [sys.executable,'-B'] + (['-O'] if sys.flags.optimize else []) + ['-m','policy.setlocaltime_construction','--table',str(t),'--extracted',str(e),'--errors',str(x),'--source-root',str(SOURCE_ROOT)]
            for success, errors in [(b'',err), (ex,err+b'error,x,x\n'), (ex,b'')]:
                e.write_bytes(success); x.write_bytes(errors)
                result = subprocess.run(cmd,cwd=ROOT,capture_output=True)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')
        self.assertEqual(before,protected())

    def test_context_pins_and_composed_caller_guard(self):
        table = csv_bytes(synthetic_rows()); ex, err = diagnostics()
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            for p in c.PINS:
                dest = repo/p; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ROOT/p,dest)
            with patch.object(c,'ROOT',repo):
                c.compare(table,ex,err,str(SOURCE_ROOT))
                for p in c.PINS:
                    path = repo/p; before = path.read_bytes(); path.write_bytes(before+b' ')
                    with self.subTest(path=p), self.assertRaises(c.ValidationError): c.compare(table,ex,err,str(SOURCE_ROOT))
                    path.write_bytes(before)
                # Isolate join guards after context approval, including caller mismatch.
                inputs = {p:(repo/p).read_bytes() for p in c.PINS}
                for file,key,value in [('reports/handler_effects.json','effect_id','setLocaltime.sysfixtime.system'), ('reports/m4-findings.json','session_class','root'), ('reports/m4-findings.json','synthetic_session',1), ('reports/handler_effects.json','profile','other')]:
                    mutated = dict(inputs); records = json.loads(inputs[file]); rid = c.EFFECT if 'handler_effects' in file else c.TAINT
                    next(r for r in records if r['record_id']==rid)[key] = value
                    mutated[file] = json.dumps(records).encode()
                    with patch.object(c,'_pinned_inputs', return_value=mutated), self.subTest(file=file,key=key), self.assertRaises(c.ValidationError): c.compare(table,ex,err,str(SOURCE_ROOT))

    def test_json_duplicate_keys(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff'):
            with self.assertRaises(c.ValidationError): c._json(data)

    def test_cli_encoding_and_no_writes(self):
        ex,err = diagnostics(); before = protected()
        with tempfile.TemporaryDirectory() as tmp:
            t,e,x = [Path(tmp)/n for n in ('table','extracted','errors')]
            t.write_bytes(csv_bytes(synthetic_rows())); e.write_bytes(ex); x.write_bytes(err)
            base = [sys.executable,'-B'] + (['-O'] if sys.flags.optimize else []) + ['-m','policy.setlocaltime_construction','--table',str(t),'--extracted',str(e),'--errors',str(x),'--source-root',str(SOURCE_ROOT)]
            for encoding in ('utf-16','utf-8-sig'):
                for form in ('json','markdown'):
                    r = subprocess.run(base+['--format',form],cwd=ROOT,capture_output=True,env=dict(os.environ,PYTHONIOENCODING=encoding))
                    self.assertEqual(r.returncode,0,r.stderr)
                    self.assertFalse(r.stdout.startswith(b'\xef\xbb\xbf'))
                    text = r.stdout.decode('utf-8')
                    if form == 'json': self.assertIs(json.loads(text)['execution_verified'],False)
                    else: self.assertIn('t.sec',text)
        self.assertEqual(before,protected())


if __name__ == '__main__': unittest.main()
