"""Retained historical OpenVPN bytes and bounded tuple mutation controls."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from tools import default_branch_sarif_tuple_proof as tuple_proof


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tools/fixtures/default-branch-tuple-proof'
SOURCE = 'usr/share/rpcd/ucode/luci.openvpn.uc'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def inputs(case):
    directory = FIXTURES / case
    source = ('openvpn-introduced.uc' if case == 'introduced'
              else 'openvpn-fixed.uc')
    return [
        (directory / 'default-suite.sarif').read_bytes(),
        (directory / 'historical-event-triage.json').read_bytes(),
        (directory / 'historical-event-manifest.json').read_bytes(),
        (directory / 'producer-receipt.json').read_bytes(),
        (FIXTURES / source).read_bytes(),
        (FIXTURES / 'source-first.json').read_bytes(),
    ]


class TupleProofTests(unittest.TestCase):
    def test_retained_introduction_positive_and_fixed_near_miss(self):
        # SARIF and producer bytes are historical. Event packets are offline
        # reference outputs from the same pinned consumer, not hosted events.
        positive = tuple_proof.verify(*inputs('introduced'), 'introduced')
        fixed = tuple_proof.verify(*inputs('fixed'), 'fixed')
        self.assertEqual(positive['oracle_sha256'], tuple_proof.ORACLE_SHA256)
        self.assertEqual(positive['source_sha256'],
                         '051c8162f826683333e11264615806df5ab08415676c0bd098921cb1b05af991')
        self.assertEqual(positive['producer_receipt_source_commit'],
                         'b45584b4e6068b9b096872dd02494a048d869c36')
        self.assertEqual(positive['result_count'], 1)
        self.assertEqual(positive['expected_and_observed'], [{
            'tuple': ['ucode/m4/direct-rpc-shell-word', SOURCE, 71, 115, 71, 132,
                      'warning'], 'count': 1,
        }])
        self.assertEqual(fixed['result_count'], 0)
        self.assertEqual(fixed['expected_and_observed'], [])
        for result in (positive, fixed):
            self.assertEqual(result['authority'], 'none')
            self.assertFalse(result['hosted_execution_authenticated'])
            self.assertFalse(result['canonical_git_provenance_verified'])

    def test_source_oracle_release_and_raw_uri_aliases(self):
        cases = []
        swapped = inputs('introduced')
        swapped[4] = inputs('fixed')[4]
        cases.append(swapped)
        changed_oracle = inputs('introduced')
        oracle = json.loads(changed_oracle[5])
        oracle['cases']['introduced']['expected_rule_results'][0]['start_column'] += 1
        changed_oracle[5] = encoded(oracle)
        cases.append(changed_oracle)
        changed_release = inputs('introduced')
        producer = json.loads(changed_release[3])
        manifest = json.loads(changed_release[2])
        producer['producer']['suite_sha256'] = '0' * 64
        manifest['producer']['suite_sha256'] = '0' * 64
        changed_release[3] = encoded(producer)
        changed_release[2] = encoded(manifest)
        cases.append(changed_release)
        for uri in (SOURCE + '\n', SOURCE.replace('/rpcd/', '%2Frpcd/'),
                    ' ' + SOURCE):
            changed_uri = inputs('introduced')
            sarif = json.loads(changed_uri[0])
            sarif['runs'][0]['results'][0]['locations'][0][
                'physicalLocation']['artifactLocation']['uri'] = uri
            changed_uri[0] = encoded(sarif)
            cases.append(changed_uri)
        for candidate in cases:
            with self.subTest(candidate=tuple_proof.digest(candidate[0])[:8]):
                with self.assertRaises(tuple_proof.TupleProofError):
                    tuple_proof.verify(*candidate, 'introduced')

    def test_duplicate_and_coordinate_mutations(self):
        for kind in ('duplicate', 'shift', 'beyond_utf16'):
            value = inputs('introduced')
            sarif = json.loads(value[0])
            result = sarif['runs'][0]['results'][0]
            region = result['locations'][0]['physicalLocation']['region']
            if kind == 'duplicate':
                sarif['runs'][0]['results'].append(result)
            elif kind == 'shift':
                region['startColumn'] += 1
            else:
                region['endColumn'] = 100000
            value[0] = encoded(sarif)
            producer = json.loads(value[3])
            producer['sarif_sha256'] = tuple_proof.digest(value[0])
            value[3] = encoded(producer)
            if kind != 'beyond_utf16':
                # Preserve exact local consumer/reference equality so the
                # source-first multiset, not stale packet bytes, rejects it.
                packet = json.loads(value[1])
                packet['sarif_sha256'] = tuple_proof.digest(value[0])
                if kind == 'duplicate':
                    packet['results_for_triage'].append(
                        dict(packet['results_for_triage'][0]))
                    packet['result_count'] = 2
                else:
                    packet['results_for_triage'][0]['start_column'] += 1
                value[1] = encoded(packet)
            with self.subTest(kind=kind):
                message = ('observed tuple multiset differs' if
                           kind != 'beyond_utf16' else 'consumer rejected')
                with self.assertRaisesRegex(tuple_proof.TupleProofError, message):
                    tuple_proof.verify(*value, 'introduced')


if __name__ == '__main__':
    unittest.main()
