"""Red-prove offline path checks without modifying the extraction gate on disk.

Run once normally and once with ``python3 -O``. A successful run confirms
that each selected test fails for the expected acceptance/rejection assertion.
"""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent.parent
test_path = HERE / 'test_extraction_gate.py'
spec = importlib.util.spec_from_file_location('test_extraction_gate', test_path)
if spec is None or spec.loader is None:
    raise RuntimeError(f'cannot load {test_path}')
test = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test)
source_path = HERE / 'extraction_gate.py'
source = source_path.read_text(encoding='utf-8')
old = 'Counter(paths) != Counter(expected)'
if source.count(old) != 1:
    raise RuntimeError('expected exactly one production multiset check')

mutations = {
    'count-only': ('len(paths) != len(expected)', [
        'test_same_count_duplicate_rejects',
        'test_same_count_foreign_path_substitution_rejects',
        'test_same_count_foreign_same_basename_substitution_rejects',
    ]),
    'set-only': ('set(paths) != set(expected)', [
        'test_missing_extra_and_duplicate_paths_reject',
    ]),
}
original = test.gate.check_results
try:
    for name, (replacement, methods) in mutations.items():
        namespace = dict(test.gate.__dict__)
        exec(compile(source.replace(old, replacement), str(source_path), 'exec'), namespace)
        test.gate.check_results = namespace['check_results']
        suite = unittest.TestSuite(test.ExtractionAcceptanceTest(method) for method in methods)
        print(f'Running {name} mutant (the following failures are expected):', flush=True)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        failed = {
            getattr(case, 'test_case', case)._testMethodName
            for case, text in result.failures if 'ValueError not raised' in text
        }
        if (result.testsRun != len(methods) or result.errors or failed != set(methods)
                or len(result.failures) != len(methods)):
            raise SystemExit(f'unexpected {name} mutation outcome')
        print(f'{name}: expected assertion failures={sorted(failed)}; errors=0', flush=True)
finally:
    test.gate.check_results = original
