#!/usr/bin/env python3
"""Full tracked-tree Ucode candidate inventory against pinned corpus manifests."""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path, PurePosixPath

EXPECTED_MANIFESTS = {
    "mvp-bounded-corpus-v0.4": "1e25cf9c2adc40c854502fed8d1ccc0977a3c4825d6ee4a1c0a543ffe0a76699",
    "mvp-bounded-corpus-v0.5-source-staged": "70ba39e2307b7c5c9905d572d85b0cca320214e48c0dc64065bad668cddb08fc",
    "mvp-bounded-corpus-v0.6": "9c004ed477665f6567a071eac45051445c61019af927bfa4e51bae4c50ebd490",
}
ROOTS = ("usr/share/ucode/", "usr/share/rpcd/ucode/", "usr/lib/ucode/")
SUFFIXES = (".uc", ".ucode", ".ut")
ROOT_PARTS = tuple(tuple(r.strip("/").split("/")) for r in ROOTS)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")

class SelectorError(ValueError): pass

def git(root, *args, binary=False):
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE) if binary else subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as e:
        detail = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else e.stderr
        raise SelectorError(f"git {' '.join(args)} failed: {detail.strip()}") from e

def safe_path(p):
    q = PurePosixPath(p)
    if not p or q.is_absolute() or ".." in q.parts or "\\" in p:
        raise SelectorError(f"unsafe tracked path: {p!r}")
    return p

def tree(root, rev):
    raw = git(root, "ls-tree", "-r", "-z", "--full-tree", rev, binary=True)
    rows = {}
    for rec in raw.split(b"\0"):
        if not rec: continue
        meta, name = rec.split(b"\t", 1)
        mode, kind, blob = meta.decode("ascii").split()
        path = safe_path(name.decode("utf-8", "surrogateescape"))
        rows[path] = {"mode": mode, "kind": kind, "git_blob": blob}
    return rows

def under_installed_root(path):
    parts=PurePosixPath(path).parts
    return any(any(parts[i:i+len(root)] == root for i in range(len(parts)-len(root)+1)) for root in ROOT_PARTS)

def shebang_match_paths(root, rev):
    # -z emits complete path records without newline-based record parsing.
    try:
        raw = subprocess.check_output(["git", "-C", str(root), "grep", "-I", "-l", "-z", "-E", "-e", "^#!.*[Uu][Cc][Oo][Dd][Ee]", rev, "--"], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1: return set()
        raise SelectorError(f"git grep failed: {e.stderr.decode(errors='replace').strip()}") from e
    prefix=rev.encode()+b":"
    found=set()
    for record in raw.split(b"\0"):
        if not record: continue
        path=record[len(prefix):] if record.startswith(prefix) else record
        found.add(path.decode("utf-8","surrogateescape"))
    return found

def blob_contents(root, blobs):
    if not blobs: return {}
    proc=subprocess.run(["git","-C",str(root),"cat-file","--batch"],input=("\n".join(blobs)+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    out=proc.stdout; pos=0; result={}
    for blob in blobs:
        end=out.index(b"\n",pos); header=out[pos:end].split(); pos=end+1
        if len(header)!=3 or header[0].decode()!=blob or header[1]!=b"blob": raise SelectorError("malformed cat-file batch output")
        size=int(header[2]); data=out[pos:pos+size]; pos+=size
        if out[pos:pos+1]!=b"\n": raise SelectorError("truncated cat-file batch output")
        pos+=1; result[blob]=data
    return result

def make_inventory(root, rev, policy, repository):
    selected = {x["source_path"]: x for x in policy.get("selected", []) if x.get("repo") == repository}
    excluded = {x["source_path"]: x for x in policy.get("excluded", []) if x.get("repo") == repository}
    all_paths = tree(root, rev); shebang_matches=shebang_match_paths(root, rev)
    candidate_paths=set(selected)|set(excluded)|shebang_matches
    for path in all_paths:
        name=PurePosixPath(path).name
        if name.endswith(SUFFIXES) or ("." not in name and under_installed_root(path)): candidate_paths.add(path)
    present={p:all_paths[p] for p in candidate_paths if p in all_paths}
    data_by_blob=blob_contents(root, sorted({x["git_blob"] for x in present.values() if x["kind"] == "blob"}))
    entries=[]
    for path in sorted(candidate_paths):
        info=present.get(path)
        if not info: continue
        baseline=selected.get(path) or excluded.get(path)
        reviewed_excluded_link = (
            info["mode"] == "120000"
            and path in excluded
            and baseline.get("reason") == "tracked symlink; target not followed"
        )
        if info["kind"] != "blob" or (info["mode"] not in ("100644", "100755") and not reviewed_excluded_link):
            raise SelectorError(f"candidate is not a regular tracked file: {path} ({info['mode']})")
        data=data_by_blob[info["git_blob"]]; name=PurePosixPath(path).name; hits=[]
        if name.endswith(SUFFIXES): hits.append("ucode_suffix")
        if info["mode"] != "120000" and path in shebang_matches and data.splitlines()[:1] and data.splitlines()[0].startswith(b"#!") and b"ucode" in data.splitlines()[0].lower(): hits.append("first_line_ucode_shebang")
        if "." not in name and under_installed_root(path): hits.append("extensionless_installed_ucode_root")
        if not hits and baseline is None: continue
        entries.append({"source_path":path,"git_blob":info["git_blob"],"sha256":hashlib.sha256(data).hexdigest(),"mode":info["mode"],"signals":hits,"explicit_policy":baseline is not None,"status":"selected" if path in selected else "excluded" if path in excluded else "unreviewed","policy":baseline})
    return entries

def compare(root, base, head, policy, raw_manifest, repository="openwrt"):
    schema = policy.get("schema")
    expected_digest = EXPECTED_MANIFESTS.get(schema)
    if expected_digest is None: raise SelectorError("unsupported policy schema")
    if hashlib.sha256(raw_manifest).hexdigest() != expected_digest: raise SelectorError(f"{schema} manifest digest mismatch")
    if json.loads(raw_manifest) != policy: raise SelectorError("parsed policy differs from pinned manifest bytes")
    for rev in (base, head):
        if not re.fullmatch(r"[0-9a-f]{40}", rev) or git(root,"rev-parse","--verify",f"{rev}^{{commit}}") != rev: raise SelectorError(f"revision must resolve as exact full SHA: {rev}")
    bi, hi = make_inventory(root, base, policy, repository), make_inventory(root, head, policy, repository)
    bm, hm = {x["source_path"]:x for x in bi}, {x["source_path"]:x for x in hi}
    events = []
    selected_paths = {x["source_path"] for x in policy.get("selected",[]) if x.get("repo")==repository}
    base_policy = {x["source_path"]:x for x in policy.get("selected",[])+policy.get("excluded",[]) if x.get("repo")==repository}
    for p in sorted(set(bm)|set(hm)|set(base_policy)):
        b,h=bm.get(p),hm.get(p)
        baseline = base_policy.get(p)
        status = h["status"] if h else b["status"] if b else "selected" if p in selected_paths else "excluded"
        reasons=[]
        if baseline is not None and not b and not h: reasons.append("baseline_identity_missing_at_base_and_head")
        if b and not h: reasons.append("candidate_removed_or_signal_lost")
        if h and not b: reasons.append("candidate_added")
        if b and h and b["signals"] != h["signals"]: reasons.append("candidate_signal_changed")
        if b and h and b["mode"] != h["mode"]: reasons.append("candidate_mode_changed")
        if b and h and b["git_blob"] != h["git_blob"]:
            if baseline is not None and status == "selected": reasons.append("selected_content_changed_scan_eligible")
            elif baseline is not None and status == "excluded": reasons.append("excluded_content_changed_review_required")
            else: reasons.append("unreviewed_candidate_content_changed")
        if h and h["status"]=="unreviewed": reasons.append("no_reviewed_disposition")
        events.append({"source_path":p,"status":status,"baseline_policy":baseline,"base":b,"head":h,"events":reasons})
    fail = any((e["status"]=="unreviewed") or any(x in e["events"] for x in ("baseline_identity_missing_at_base_and_head","candidate_removed_or_signal_lost","candidate_added","candidate_signal_changed","candidate_mode_changed","excluded_content_changed_review_required","unreviewed_candidate_content_changed")) for e in events)
    return {"schema":"full-tree-ucode-candidates-v1","policy_schema":policy["schema"],"policy_sha256":hashlib.sha256(raw_manifest).hexdigest(),
            "repository":repository,"base_commit":base,"base_tree":git(root,"rev-parse",f"{base}^{{tree}}"),"head_commit":head,"head_tree":git(root,"rev-parse",f"{head}^{{tree}}"),
            "base_candidate_count":len(bi),"head_candidate_count":len(hi),"head_selected_count":sum(x["status"]=="selected" for x in hi),
            "head_excluded_count":sum(x["status"]=="excluded" for x in hi),"head_unreviewed_count":sum(x["status"]=="unreviewed" for x in hi),
            "missing_baseline_count":sum("baseline_identity_missing_at_base_and_head" in x["events"] for x in events),
            "events":events,"fail_closed":fail,"status":"review_required" if fail else "inventory_ready",
            "limitations":["Candidate signals do not prove installability or installed bytes.","Recipe mapping/configuration inference is not implemented; policy rows only preserve dispositions in the selected pinned manifest.","Each invocation covers one repository. Package-feed mapping, CodeQL execution, producer-to-consumer handoff, and Gate 8 remain out of scope."]}

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("manifest",type=Path); ap.add_argument("repository",choices=("openwrt","luci")); ap.add_argument("checkout",type=Path); ap.add_argument("base_sha"); ap.add_argument("head_sha"); ap.add_argument("output",type=Path); a=ap.parse_args()
    try:
        raw=a.manifest.read_bytes(); result=compare(a.checkout,a.base_sha,a.head_sha,json.loads(raw),raw,a.repository)
        a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps({k:v for k,v in result.items() if k!="events"},indent=2)); return 1 if result["fail_closed"] else 0
    except (OSError,json.JSONDecodeError,SelectorError) as e: print(f"full-tree selector failed closed: {e}",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
