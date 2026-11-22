# LuCI markup extraction assessment

Fresh paired observation for [OpenWrt #68](https://github.com/lucas-albers-lz4/codeql-openwrt/issues/68), 2026-11-21. The 12 selected inventory identities all appear exactly once in `SuccessfullyExtractedFiles`, and the whole-database `ExtractionErrors` result has zero rows. Thus each has zero reported extraction errors in this run. This is a diagnostic-level observation, not a complete AST correctness proof. Raw receipt, diagnostic outputs and a bounded AST query are retained in [evidence](../evidence/markup-profile-0a6612f/).

Consumer base `d37adeadaf836ba97049f75087a348165027f7f9`, profile `luci-ssl-25.12`, inventory `inventory:luci-ssl-files-v1`, corpus lock SHA-256 `b4cbdabb76df90a807aba7d42ae675198c7b7b09c3b84db259a3a4c941b0ea9a`. LuCI source commit `b2e0be4b46ec0fd43394c081fa7c50657af14011`; producer commit `0a6612fe0e66351a0ccda43ad5b51f5ef5a2724e`; grammar `4a243af329fae2f4ff01e0fc80133cbab8314600`; shared extractor dependency `ce29d8a59af0d25517c622469db17aad826b8d7f`; CodeQL CLI 2.27.4. The producer pack was freshly built on macOS using `scripts/clone-grammar.sh` then `scripts/create-extractor-pack.sh`; extractor SHA-256 `35aeb3a59305c7fb21b9ead30d658add5d255645f3f73efc877f5363abf242a8`. Producer tracked tree remained clean.

The stage is a byte-for-byte source copy mapped by the inventory's `luci.mk ucode/ -> installed` rule, not a package build or live installation. The `SubstituteVersion` build step was not run. Every staged file matched its pinned source bytes; columns give source Git blob and SHA-256, also the staged SHA-256. All installed paths below are relative to the staged root when selected; the actual canonical source identities in the retained output begin `/private/tmp/openwrt68-stage`. No other files were staged.

| Installed identity | Pinned LuCI source | Git blob | Source and stage SHA-256 | Diagnostic |
| --- | --- | --- | --- | --- |
| `/usr/share/ucode/luci/uhttpd.uc` | `modules/luci-base/ucode/uhttpd.uc` | `df1ecc78657d9db618ab253c71497db4c66335fc` | `a2b2694f52c021af16dd06ac8c988b8a0a726d9e8186d308708268ebb8849493` | extracted; 0 |
| `/usr/share/ucode/luci/template/csrftoken.ut` | `modules/luci-base/ucode/template/csrftoken.ut` | `4e96eebe905758bb607a324cd10d0cf43e4eec6e` | `a2f223208d9ff2c3e1bfa808f11d74636028b4902973afb5b7f336328f7e2160` | extracted; 0 |
| `/usr/share/ucode/luci/template/error404.ut` | `modules/luci-base/ucode/template/error404.ut` | `90c3d3784bb60ec8c4c6c189cf2eebd7cda9076d` | `8fa2306435be3aca3ca59b09adaaa0190292c6cfe2fecda9df4eb3eeac5b8552` | extracted; 0 |
| `/usr/share/ucode/luci/template/error500.ut` | `modules/luci-base/ucode/template/error500.ut` | `e0d4d48ab741cb5fd9416de17ef9030a7a757bc1` | `6c7a519229524d7a34b18c5da97cb8b05f622ee0938fe1a4b2d2516a6adf1887` | extracted; 0 |
| `/usr/share/ucode/luci/template/footer.ut` | `modules/luci-base/ucode/template/footer.ut` | `0ab06ae0b9380b12c6351061b089a397a14ff0d7` | `5625f938d625ff406e53434d37aa7643cc09e11f74379887a4ba154021240495` | extracted; 0 |
| `/usr/share/ucode/luci/template/header.ut` | `modules/luci-base/ucode/template/header.ut` | `f23e5e45c88211d3d500193407f9277f1912c784` | `67132f2d1c1cf743f3e4ce11d660a5a2569b461804a63914061fe956171be6c2` | extracted; 0 |
| `/usr/share/ucode/luci/template/sysauth.ut` | `modules/luci-base/ucode/template/sysauth.ut` | `babba2ecb522b7acec2e20e4ea071c15b74c307f` | `8c1dcf98cd29410021ed4f5f9dc668f8c70c0227f39f97f60f7205f9d52fa5bb` | extracted; 0 |
| `/usr/share/ucode/luci/template/view.ut` | `modules/luci-base/ucode/template/view.ut` | `a8562844baf7d155c8cd682939f26e67a2a208ac` | `785bf7d4cceb5cdd9f113cbede0bde5b69e35b69cc1b51d2e498665d50091d62` | extracted; 0 |
| `/usr/share/ucode/luci/template/admin_status/index.ut` | `modules/luci-mod-status/ucode/template/admin_status/index.ut` | `dafb427bf48b4da1e09ead45b97e55791804f20d` | `652842b1e54f8a2904458ae1f5693ddfc68b97f106d8b8ff48a4d8747d673019` | extracted; 0 |
| `/usr/share/ucode/luci/template/themes/bootstrap/header.ut` | `themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/header.ut` | `3486a412078c9fe5df3159b4691ffeb7de8794c0` | `eca05b1e4d8391e36a08bcd0b3d0135d2addb37b9e574bd7db98d56f4835e0a3` | extracted; 0 |
| `/usr/share/ucode/luci/template/themes/bootstrap/footer.ut` | `themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/footer.ut` | `d51079b6fa8e89e5119514c7730f982a5cd671a3` | `b5cb417ca73c02226679ab2412e272dcf6851eee134c521fc316c39a81ecfa4e` | extracted; 0 |
| `/usr/share/ucode/luci/template/themes/bootstrap/sysauth.ut` | `themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/sysauth.ut` | `e311f2d03fe28bccddf91c860ff66219b5415d50` | `7e4702c063c95734ec3157121dc59802ff51ed2c1b73c405cd9831ddd2e0c337` | extracted; 0 |

The routing receipt has 12 inputs, 12 markup, zero plain, excluded, uncertain or duplicate, and exactly the 12 selected paths. Eleven use `ut_markup_extension`; `uhttpd.uc` uses `markup_tag_content`. All retain `inconclusive` / `markup_not_modeled`. The selected uhttpd query returned the independently specified first import at line 3, columns 1–39, parent `Markup`, and the three additional producer smoke rows (see CSV). That checks a bounded selected observation, not full tree fidelity across all files; clause/source text and negative acceptance controls were not checked here.

Reproduction on a machine with the pinned prerequisites, using fresh paths (the commands assume these names are unused):

```sh
git clone https://github.com/lucas-albers-lz4/codeql-ucode.git /tmp/openwrt68-producer
git -C /tmp/openwrt68-producer checkout --detach 0a6612fe0e66351a0ccda43ad5b51f5ef5a2724e
(cd /tmp/openwrt68-producer && bash scripts/clone-grammar.sh && bash scripts/create-extractor-pack.sh)
git clone https://github.com/openwrt/luci.git /tmp/openwrt68-luci
git -C /tmp/openwrt68-luci checkout --detach b2e0be4b46ec0fd43394c081fa7c50657af14011
python3 - <<'PYCODE'
import json, pathlib, shutil
rows = [r for r in json.load(open('reports/m4-luci-ssl-files.json')) if r.get('classification') == 'markup']
assert len(rows) == 12 and len({r['fs_path'] for r in rows}) == 12
for r in rows:
    src = pathlib.Path('/tmp/openwrt68-luci') / r['source']
    dst = pathlib.Path('/tmp/openwrt68-stage') / r['fs_path'].lstrip('/')
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    assert src.read_bytes() == dst.read_bytes()
PYCODE
codeql database init /tmp/openwrt68-db2 --language=ucode --search-path=/tmp/openwrt68-producer/extractor-pack --source-root=/tmp/openwrt68-stage
CODEQL_UCODE_STAGED_ROOT=/tmp/openwrt68-stage codeql database index-files /tmp/openwrt68-db2 --language=ucode --include='**/*.uc' --include='**/*.ut' --working-dir=/tmp/openwrt68-stage
cp /tmp/openwrt68-db2/trap/ucode/routing.json /tmp/openwrt68-routing.json
codeql database finalize /tmp/openwrt68-db2
for q in SuccessfullyExtractedFiles ExtractionErrors; do
  codeql query run "/tmp/openwrt68-producer/ql/src/diagnostics/$q.ql" --database=/tmp/openwrt68-db2 --search-path=/tmp/openwrt68-producer/extractor-pack --output="/tmp/openwrt68-$q.bqrs" --threads=1 --ram=2048
  codeql bqrs decode --format=json --entities=url,string "/tmp/openwrt68-$q.bqrs" > "/tmp/openwrt68-$q.json"
done
codeql query run /tmp/openwrt68-producer/ql/src/markup-real-issue56-test.ql --database=/tmp/openwrt68-db2 --search-path=/tmp/openwrt68-producer/extractor-pack --output=/tmp/openwrt68-ast.bqrs --threads=1 --ram=2048
codeql bqrs decode --format=csv /tmp/openwrt68-ast.bqrs > /tmp/openwrt68-ast.csv
```

Put the pinned CLI on `PATH`. Validate the newly generated outputs with the retained checker (the retained defaults refer to the original run and therefore its canonical stage path):

```sh
python3 evidence/markup-profile-0a6612f/validate.py --source /tmp/openwrt68-luci --stage /tmp/openwrt68-stage --receipt /tmp/openwrt68-routing.json --extracted /tmp/openwrt68-SuccessfullyExtractedFiles.json --errors /tmp/openwrt68-ExtractionErrors.json
python3 evidence/markup-profile-0a6612f/test_validate.py
```

The checker rejects duplicate JSON object keys at any depth in the manifest, receipt, and diagnostic inputs. It compares source and stage hashes to the retained manifest, the exact staged file set, full canonical identities and cardinality, receipt fields, and the empty error table. Synthetic negative controls exercise missing, unexpected and duplicate diagnostic identities, malformed diagnostic schemas and success tuples, changed locations, a nonempty error table, changed receipt status and routing reason, changed stage bytes, an extra staged file, and extra or selected symlinks. The checker compares the complete expected diagnostic tuples and lexical stage file set and rejects stage symlinks. They exercise this assessment validator, not producer parser recovery. The diagnostic queries have no per-file error rows here; zero per-file follows from the empty global table and the exact selected set. The output paths are run-specific.

This assessment does not alter the historical inventory or coverage records. Historical statements that markup extraction was unstaffed describe the earlier inventory, not current producer availability. The existing receipt and consumer contract still say `inconclusive` / `markup_not_modeled`; this observation does not establish a new consumer reporting contract, markup CFG or data flow, dispatcher behavior, runtime behavior, or security coverage. The three absent extractor gate cases were not invented. The original assessment did not include a malformed-parser control, independent full AST oracle, package installation, CI, or independent review.
