from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def need(condition, message):
    if not condition:
        raise ValueError(message)

def tool(path):
    resolved = Path(path).resolve(strict=True)
    return {'path':str(resolved),'sha256':sha(resolved)}

def main():
    artifact_id = int(sys.argv[1])
    artifact_sha = sys.argv[2]
    work = Path(__file__).resolve().parent
    raw_root = Path('/private/tmp/review173-dockerman-retry.wtpEepuR')
    raw = raw_root / 'retained/dockerman'
    manifest = json.loads((raw/'manifest.json').read_bytes())
    need(manifest['status']=='dockerman_package_compared_review_required', 'requires verified complete hosted result')
    need(sha(raw_root/'outer.zip')==artifact_sha, 'original artifact ZIP digest differs')
    paths = {
        'oracle':Path('/Users/lalbers/gitroot/ucode/.worktrees/openwrt-issue173-dockerman-postguard-20261126/tools/luci-app-metadata-probe/source-oracle.json'),
        'archive':Path('/Users/lalbers/gitroot/ucode/.worktrees/openwrt-issue173-dockerman-postguard-20261126/tools/luci-base-inventory/archive.py'),
        'comparator':Path('/Users/lalbers/gitroot/ucode/.worktrees/openwrt-issue173-dockerman-postguard-20261126/tools/luci-dockerman-build/compare.py'),
        'ipk':raw/'luci-app-dockerman.ipk',
        'prepared':raw/'dockerman-prepared',
        'stage':raw/'dockerman-stage',
        'source':Path('/Users/lalbers/gitroot/ucode/coverage-wave-work/issue172-20261125/luci'),
        'config':raw/'config-final',
        'hosted_comparison_receipt':raw/'dockerman-package-comparison.json',
        'prepared_inventory':raw/'dockerman-prepared-inventory.json',
        'stage_inventory':raw/'dockerman-stage-inventory.json',
    }
    known = {
        'oracle':'a5ab0a2b8f0099073a040b57ec4be3324a874d2f67ec3951a62a18cfa886cf4f',
        'archive':'224e748846138261c2d709b2932764ffeaabfd90378ccf2a8ffa7476e6630100',
        'comparator':'f8d38548b24cef4fb8493d0f7e564bf082061d566efcdb1bfca567008631ffae',
        'ipk':manifest['ipk_sha256'],
        'config':manifest['config_sha256'],
        'hosted_comparison_receipt':manifest['comparison_sha256'],
        'prepared_inventory':manifest['output_sha256']['dockerman-prepared-inventory.json'],
        'stage_inventory':manifest['output_sha256']['dockerman-stage-inventory.json'],
    }
    for name, digest in known.items():
        need(sha(paths[name])==digest, 'retained input digest differs '+name)
    root=work/'dockerman'
    root.mkdir()
    for name in ('home','tmp'):
        (root/name).mkdir()
    tools={'python3':tool(shutil.which('python3')), 'git':tool(shutil.which('git')), 'time':tool('/usr/bin/time'), 'shell':tool('/bin/sh')}
    for name in ('python3','git'):
        found=tools[name]
        found['version']=subprocess.check_output([found['path'],'--version']).decode().strip()
    output=root/'comparison.stdout'
    time_output=root/'comparison.time-and-stderr'
    tool_stderr=root/'comparison.stderr'
    receipt=root/'comparison.receipt.json'
    argv=[tools['time']['path'],'-l','/bin/sh','-c','output=$1; shift; exec "$@" 2>"$output"','sh',str(tool_stderr),
          tools['python3']['path'],'-I','-B',str(paths['comparator']),'--luci',str(paths['source']),'--prepared',str(paths['prepared']),
          '--stage',str(paths['stage']),'--ipk',str(paths['ipk']),'--config',str(paths['config']),'--receipt',str(receipt)]
    env={'PATH':str(Path(tools['git']['path']).parent)+':/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','HOME':str(root/'home'),'TMPDIR':str(root/'tmp')}
    head=subprocess.check_output([tools['git']['path'],'-C',str(paths['source']),'rev-parse','HEAD','HEAD^{tree}'],env=env).decode().splitlines()
    need(head==['cb87fe60e1e2e052af36a93647f2264577829e0a','1d7bf89bc8708fca69d005b0690ca823c9071692'], 'source revision/tree differs')
    started=datetime.now(timezone.utc).isoformat()
    with output.open('xb') as stdout, time_output.open('xb') as stderr:
        run=subprocess.run(argv,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
    ended=datetime.now(timezone.utc).isoformat()
    record={'schema':'issue173-offline-comparison-timing-v1','argv':argv,'cwd':str(root),'env':env,'tools':tools,
        'started_utc':started,'completed_utc':ended,'exit':run.returncode,'platform':platform.platform(),
        'release':'macOS 15.8.2 (24H232)','cpu':platform.machine(),'input_paths':{k:str(v) for k,v in paths.items()},
        'inputs':known,'tool_driver_sha256':sha(Path(__file__)),
        'hosted_source':{'run':45806390805,'attempt':1,'artifact':artifact_id,'head':'9d5e323060c16ad50fc925dfc5d7dab7ba6c3c91','artifact_zip_sha256':artifact_sha,
            'app_receipt_sha256':manifest['comparison_sha256']},
        'outputs':{p.name:sha(p) for p in (output,time_output,tool_stderr,receipt) if p.exists()},
        'scope':'single offline local comparison of pinned Git, actual archived prepared and stage regular files, and exact IPK. Cache state uncontrolled. Original hosted comparator elapsed not measured.',
    }
    with (root/'invocation.json').open('x') as out:
        json.dump(record,out,sort_keys=True,indent=2)
        out.write('\n')
    need(run.returncode==0 and tool_stderr.read_bytes()==b'', 'offline process failed or wrote stderr')
    need(receipt.read_bytes()==paths['hosted_comparison_receipt'].read_bytes(),'offline comparison receipt differs')
    print(time_output.read_text(),end='')
    print('byte-identical receipt',sha(receipt),'invocation',sha(root/'invocation.json'))

if __name__=='__main__':
    main()
