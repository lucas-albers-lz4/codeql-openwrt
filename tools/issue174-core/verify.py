#!/usr/bin/env python3
"""Check bounded #174 observations against a reviewed pre-run lock (no scan)."""
import argparse
import json
import math
from pathlib import Path
import check
import prepare

PHASES=('resolve-query','resolve-success','resolve-errors','database-init','database-index','database-finalize',
        'success-query','success-decode','errors-query','errors-decode','target-query','target-decode')
OUTPUTS=('routing','successful','errors','query')
KNOWN_CACHE_WARNING='WARNING: Not caching stages during query-loading, since max heap size is only 1816 MB.'
QUERY_PHASES={'success-query','errors-query','target-query'}
def validate_commands(lock, commands, cli, producer, stage, pack, dependencies):
    expected=lock.get('phase_argv');rows=commands.get('commands')
    check.require(isinstance(expected,dict) and set(expected)==set(PHASES),'phase command lock differs')
    check.require(isinstance(rows,list) and len(rows)==len(PHASES),'command receipt count differs')
    for name,row in zip(PHASES,rows):
        check.require(isinstance(row,dict) and row.get('label')==name and row.get('argv')==expected[name] and isinstance(row.get('argv'),list) and row['argv'], 'command identity or order differs: '+name)
        check.require(row.get('cwd')==lock.get('cwd') and row.get('env')==lock.get('env'), 'command environment differs: '+name)
        check.require(type(row.get('exit')) is int and row['exit']==0,'command failed: '+name)
        elapsed=row.get('elapsed_seconds');rss=row.get('peak_rss_bytes')
        check.require(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0, 'missing phase elapsed: '+name)
        check.require('peak_rss_bytes' in row and (type(rss) is int and rss>=0 or rss is None and isinstance(row.get('rss_note'),str) and row['rss_note']), 'missing or invalid peak RSS: '+name)
    argv={row['label']:row['argv'] for row in rows}
    check.require(all(a[0]==str(cli) for a in argv.values()),'unreviewed command executable')
    target=str(producer/'ql/src/m4/RequestArgsExec.ql')
    success=str(producer/'ql/src/diagnostics/SuccessfullyExtractedFiles.ql')
    errors=str(producer/'ql/src/diagnostics/ExtractionErrors.ql')
    run=Path(lock['run_root']);expected_search=':'.join(map(str,(pack,producer/'ql/lib',producer/'ql/src')))
    check.require(lock.get('cwd')==str(producer), 'command cwd differs')
    env=lock.get('env');check.require(isinstance(env,dict) and env=={'CODEQL_UCODE_STAGED_ROOT':str(stage),'HOME':str(run/'home'),'TMPDIR':str(run/'tmp'),'XDG_CACHE_HOME':str(run/'cache'),'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}, 'command environment boundary differs')
    additional=lock.get('additional_packs');check.require(isinstance(additional,list) and additional, 'dependency pack paths missing')
    for item in additional:
        p=Path(item);check.require(p.is_absolute() and p.resolve(strict=True)==p and p.is_dir() and p.is_relative_to(dependencies), 'dependency path differs')
    required_search='--search-path='+expected_search;required_additional='--additional-packs='+':'.join(additional)
    resolvers=lock.get('resolver_paths');check.require(isinstance(resolvers,dict) and set(resolvers)=={'query','successful','errors'}, 'resolver paths missing')
    for name,path in (('query',target),('success',success),('errors',errors)):
        a=argv['resolve-'+name]
        check.require(a[1:3]==['resolve','library-path'] and a.count('--query='+path)==1 and a.count(required_search)==1 and a.count(required_additional)==1 and '--format=json' in a and a.count('--common-caches='+str(run/'cache/queries'))==1 and a.count('--compilation-cache='+str(run/'cache/compile'))==1 and a.count('--no-default-compilation-cache')==1, 'query resolver differs: '+name)
    check.require(argv['database-init'][1:3]==['database','init'] and argv['database-init'].count('--source-root='+str(stage))==1 and argv['database-init'].count('--language=ucode')==1 and argv['database-init'].count('--search-path='+str(pack))==1 and argv['database-init'].count('--common-caches='+str(run/'cache/database'))==1, 'database source root or extractor differs')
    check.require(argv['database-index'][1:3]==['database','index-files'] and argv['database-index'].count('--working-dir='+str(stage))==1 and argv['database-index'].count('--include=**/*')==1 and argv['database-index'].count('--language=ucode')==1 and argv['database-index'].count('--common-caches='+str(run/'cache/database'))==1, 'index selection differs')
    bqrs=lock.get('bqrs_paths'); outputs=lock.get('output_paths');db=lock.get('database_path')
    check.require(isinstance(bqrs,dict) and set(bqrs)=={'successful','errors','query'} and isinstance(db,str) and db.startswith('/'),'BQRS/database paths missing')
    check.require(argv['database-finalize'][1:3]==['database','finalize'] and db in argv['database-finalize'] and argv['database-finalize'].count('--common-caches='+str(Path(lock['run_root'])/'cache/database'))==1,'database finalize differs')
    for prefix,query,name in (('success',success,'successful'),('errors',errors,'errors'),('target',target,'query')):
        run=argv[prefix+'-query'];decode=argv[prefix+'-decode']
        check.require(run[1:3]==['query','run'] and run.count(query)==1 and run.count('--database='+db)==1 and run.count('--output='+bqrs[name])==1 and run.count(required_search)==1 and run.count(required_additional)==1 and run.count('--common-caches='+str(Path(lock['run_root'])/'cache/queries'))==1 and run.count('--compilation-cache='+str(Path(lock['run_root'])/'cache/compile'))==1 and '--no-default-compilation-cache' in run, 'query command differs: '+prefix)
        check.require(decode[1:3]==['bqrs','decode'] and bqrs[name] in decode and '--format=json' in decode and '--entities=id,url,string' in decode and '--output='+outputs[name] in decode,'decode command differs: '+prefix)
    check.require(db in argv['database-init'] and db in argv['database-index'],'database identities differ')
    for name,a in argv.items():
        options=[x.split('=',1)[0] for x in a if x.startswith('--')]
        check.require(len(options)==len(set(options)), 'duplicate command option: '+name)
    return [{'label':r['label'],'elapsed_seconds':r['elapsed_seconds'],'peak_rss_bytes':r.get('peak_rss_bytes')} for r in rows]

def validate_phase_artifact(phase, row, path):
    file=check.safe_file(Path(path));actual=check.digest(file.read_bytes())
    check.require(row.get('artifacts')=={path:actual}, 'phase artifact digest differs: '+phase)
    if phase=='database-index':check.require(row.get('raw_routing_sha256')==actual, 'raw/retained routing digest differs')
    return actual


def validate_logs(lock, rows):
    run=Path(lock['run_root']);result={}
    resolver_names={'resolve-query':'query','resolve-success':'successful','resolve-errors':'errors'}
    for row in rows:
        label=row['label']
        for stream in ('stdout','stderr'):
            expected=(Path(lock['resolver_paths'][resolver_names[label]]) if stream=='stdout' and label in resolver_names
                      else run/'output'/'logs'/(label+'.'+stream))
            actual=row.get(stream+'_path');check.require(actual==str(expected), 'command log path differs: '+label+' '+stream)
            path=check.safe_file(expected);raw=path.read_bytes();sha=check.digest(raw)
            check.require(row.get(stream+'_sha256')==sha, 'command log digest differs: '+label+' '+stream)
            text=raw.decode('utf-8',errors='replace')
            warnings=[line for line in text.splitlines() if 'WARNING:' in line.upper()]
            check.require(not any(token in text.upper() for token in ('ERROR:', 'FATAL:')), 'command error requires review: '+label)
            if stream=='stdout':
                check.require(not warnings, 'command warning requires review: '+label)
            else:
                check.require(not warnings or label in QUERY_PHASES and warnings==[KNOWN_CACHE_WARNING], 'command warning requires review: '+label)
                check.require(row.get('classified_warnings',[])==warnings, 'warning classification differs: '+label)
                if warnings:
                    artifacts=row.get('artifacts');check.require(row.get('exit')==0 and isinstance(artifacts,dict) and len(artifacts)==1, 'warned query lacks valid artifact: '+label)
                    artifact_path,artifact_sha=next(iter(artifacts.items()));file=check.safe_file(Path(artifact_path))
                    check.require(check.digest(file.read_bytes())==artifact_sha, 'warned query artifact differs: '+label)
            result[str(path)]=sha
    return result


def main():
    parser=argparse.ArgumentParser()
    for name in ('lock','ipk','receipt','producer','cli','pack','dependencies','stage','commands','routing','successful','errors','query'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--lock-sha256',required=True)
    args=parser.parse_args()
    lock_data=check.safe_file(args.lock).read_bytes()
    check.require(check.digest(lock_data)==prepare.need_digest(args.lock_sha256,'lock'),'run lock digest differs')
    lock=check.json_object(lock_data)
    prepare.validate_layout(lock,args.stage,before=False)
    provider=prepare.preflight(lock,args.ipk,args.receipt,args.producer,args.cli,args.pack,args.dependencies)
    staged=check.safe_file(args.stage/check.IPK_SOURCE)
    check.require(staged.read_bytes()==provider, 'stage not exact package member')
    outputs=lock.get('output_paths');check.require(isinstance(outputs,dict) and set(outputs)==set(OUTPUTS),'locked output paths differ')
    paths={}
    for name in OUTPUTS:
        p=check.safe_file(getattr(args,name));check.require(str(p)==outputs[name],'output path differs: '+name);paths[name]=p
    command_path=check.safe_file(args.commands);check.require(str(command_path)==lock.get('commands_path'),'commands path differs')
    command_doc=check.json_object(command_path.read_bytes())
    costs=validate_commands(lock,command_doc,args.cli,args.producer,args.stage,args.pack,args.dependencies)
    rows={row['label']:row for row in command_doc['commands']}
    log_hashes=validate_logs(lock,command_doc['commands'])
    artifact_hashes={}
    for phase,path in [('database-index',outputs['routing']),('database-finalize',str(Path(lock['database_path'])/'src.zip')),
                       ('success-query',lock['bqrs_paths']['successful']),('errors-query',lock['bqrs_paths']['errors']),('target-query',lock['bqrs_paths']['query']),
                       ('success-decode',outputs['successful']),('errors-decode',outputs['errors']),('target-decode',outputs['query'])]:
        artifact_hashes[path]=validate_phase_artifact(phase,rows[phase],path)
    resolved_expected=lock.get('resolved_library_paths')
    check.require(isinstance(resolved_expected,list) and len(resolved_expected)==len(set(resolved_expected)) and str(args.producer/'ql/src') in resolved_expected and str(args.producer/'ql/lib') in resolved_expected, 'resolved dependency inventory missing')
    for item in resolved_expected:
        p=Path(item);check.require(p.is_absolute() and p.resolve(strict=True)==p and p.is_dir() and (p.is_relative_to(args.producer) or p.is_relative_to(args.dependencies)), 'resolved library path outside pinned roots')
    for phase,name,relative in [('resolve-query','query','m4/RequestArgsExec.ql'),('resolve-success','successful','diagnostics/SuccessfullyExtractedFiles.ql'),('resolve-errors','errors','diagnostics/ExtractionErrors.ql')]:
        path=check.safe_file(Path(lock['resolver_paths'][name]));actual=check.digest(path.read_bytes())
        check.require(rows[phase].get('artifacts')=={str(path):actual}, 'resolver output digest differs: '+phase)
        data=check.json_object(path.read_bytes())
        check.require(data.get('libraryPath')==resolved_expected and data.get('dbscheme')==str(args.producer/'ql/lib/ucode.dbscheme') and data.get('relativeName')=='lucas-albers-lz4/ucode-queries/'+relative and data.get('qlPackName')=='lucas-albers-lz4/ucode-queries' and data.get('compilationCache')==[str(Path(lock['run_root'])/'cache/compile')], 'resolver identity differs: '+phase)
        artifact_hashes[str(path)]=actual
    source_archive_sha=check.validate_source_archive(args.stage,Path(lock['database_path'])/'src.zip')
    check.require(artifact_hashes[str(Path(lock['database_path'])/'src.zip')]==source_archive_sha, 'source archive digest differs')
    values={name:check.json_object(path.read_bytes()) for name,path in paths.items()}
    result=check.check_observations(args.stage,values['routing'],values['successful'],values['errors'],values['query'],check.oracle())
    result.update({'lock_sha256':args.lock_sha256,'ipk_sha256':lock['ipk_sha256'],'source_oracle_sha256':check.ORACLE_SHA,
                   'producer_commit':check.PRODUCER,'query_sha256':check.QUERY_SHA,
                   'output_sha256':{name:check.digest(path.read_bytes()) for name,path in paths.items()},
                   'warnings':{r['label']:r['classified_warnings'] for r in command_doc['commands'] if r.get('classified_warnings')},
                   'commands_sha256':check.digest(command_path.read_bytes()),'phase_logs_sha256':log_hashes,'phase_artifacts_sha256':artifact_hashes,'phase_costs':costs})
    print(json.dumps(result,sort_keys=True,indent=2))
if __name__=='__main__':main()
