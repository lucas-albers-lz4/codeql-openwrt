#!/usr/bin/env python3
"""Compare a bounded v0.4 source policy with a pinned OpenWrt or LuCI Git head.

Only baseline identities and candidate paths in the event's first-parent diff
are examined; this is not a full source discovery scan.
"""
from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from pathlib import Path, PurePosixPath
REPOS = {"openwrt", "luci"}
class DriftError(ValueError): pass
def git(root: Path, *args: str) -> str:
    try: return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as e: raise DriftError(f"git {' '.join(args)} failed: {e.stderr.strip()}") from e
def safe_path(s: str) -> str:
    p=PurePosixPath(s)
    if p.is_absolute() or ".." in p.parts or not s: raise DriftError(f"unsafe source path: {s!r}")
    return s
def file_identity(root: Path, commit: str, path: str):
    path=safe_path(path)
    try:
        blob=git(root,"rev-parse",f"{commit}:{path}")
        raw=subprocess.check_output(["git","-C",str(root),"show",f"{commit}:{path}"])
    except (DriftError,subprocess.CalledProcessError): return None
    return {"path":path,"git_blob":blob,"sha256":hashlib.sha256(raw).hexdigest()}
def candidate(path: str) -> bool:
    name=PurePosixPath(path).name
    return PurePosixPath(name).suffix in {".uc",".ut"} or ("." not in name and name not in {"Makefile","Config.in"})
def analyze(manifest: dict, repo_name: str, root: Path, event_sha: str) -> dict:
    if manifest.get("schema")!="mvp-bounded-corpus-v0.4": raise DriftError("unsupported baseline manifest schema")
    if repo_name not in REPOS: raise DriftError("repo must be openwrt or luci")
    commit=git(root,"rev-parse","--verify",f"{event_sha}^{{commit}}")
    if commit!=event_sha or git(root,"rev-parse","HEAD")!=event_sha: raise DriftError("checkout HEAD must equal the full event commit SHA")
    if git(root,"status","--porcelain=v1"): raise DriftError("event checkout must be clean")
    selected=[x for x in manifest.get("selected",[]) if x.get("repo")==repo_name]
    excluded=[x for x in manifest.get("excluded",[]) if x.get("repo")==repo_name]
    names={x["source_path"]:x for x in selected+excluded if "source_path" in x}
    resolved=[]; removed=[]; changed=[]
    for path,item in names.items():
        now=file_identity(root,commit,path)
        record={"source_path":path,"baseline_class":"selected" if item in selected else "excluded","package_owner":item.get("package_owner"),"config_condition":item.get("config_condition"),"reason":item.get("reason"),"expected_route":item.get("expected_route"),"baseline_source_commit":item.get("source_commit"),"baseline_git_blob":item.get("git_blob"),"baseline_sha256":item.get("source_sha256",item.get("sha256")),"event_identity":now}
        if now is None: removed.append(record)
        else:
            resolved.append(record)
            if record["baseline_git_blob"] and now["git_blob"]!=record["baseline_git_blob"]: changed.append(record)
    diffs=[]
    if git(root,"rev-list","--count",commit)!="1":
        for line in git(root,"diff","--name-status","--find-renames",f"{commit}^",commit).splitlines():
            f=line.split("\t"); st=f[0]
            if st.startswith("R") and len(f)==3: diffs.append({"status":"renamed","old_path":f[1],"new_path":f[2]})
            elif len(f)==2: diffs.append({"status":"added" if st.startswith("A") else "removed" if st.startswith("D") else "modified","path":f[1]})
    drift=[]
    for d in diffs:
        path=d.get("new_path",d.get("path","")); old=d.get("old_path")
        if d["status"]=="removed" and path in names: drift.append({**d,"class":"removed_baseline_identity"})
        elif d["status"]=="renamed" and (old in names or candidate(path) or candidate(old)): drift.append({**d,"class":"renamed_or_candidate_path"})
        elif d["status"]=="added" and candidate(path): drift.append({**d,"class":"new_candidate"})
        elif d["status"]=="modified" and path in names: drift.append({**d,"class":"baseline_identity_content_changed"})
    fail=bool(drift or removed or changed)
    return {"schema":"source-policy-drift-v1","baseline_schema":manifest["schema"],"repository":repo_name,"event_commit":commit,"event_tree":git(root,"rev-parse",f"{commit}^{{tree}}"),"baseline_selected_count_for_repo":len(selected),"baseline_excluded_count_for_repo":len(excluded),"selected_and_excluded_identities":resolved,"removed_baseline_identities":removed,"changed_selected_or_excluded":changed,"drift":drift,"status":"review_required" if fail else "no_bounded_drift_observed","fail_closed":fail,"limitations":["Only baseline identities and candidate paths changed in the event's first-parent diff are examined.","No full-tree discovery, install-path inference, package condition evaluation, extraction, CodeQL, SARIF, or consumer handoff is performed.","Extensionless candidate heuristic is intentionally broad and requires review; unrecognized source layouts may be missed."]}
def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("manifest",type=Path); p.add_argument("repository",choices=sorted(REPOS)); p.add_argument("checkout",type=Path); p.add_argument("event_sha"); p.add_argument("output",type=Path); a=p.parse_args()
    try:
        r=analyze(json.loads(a.manifest.read_text()),a.repository,a.checkout,a.event_sha); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(r,indent=2)+"\n"); print(json.dumps(r,indent=2)); return 1 if r["fail_closed"] else 0
    except (OSError,json.JSONDecodeError,DriftError) as e: print(f"source-policy drift failed closed: {e}",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
