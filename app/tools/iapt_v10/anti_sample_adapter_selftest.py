#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
TOOLS=HERE.parent
for item in (HERE,TOOLS):
    if str(item) not in sys.path: sys.path.insert(0,str(item))
from iapt_anti_sample_profiles import resolve_profile
from iapt_hidden_resource_restore import build_normalized_apk
EXPECTED={
 "shishe":"64586ad7898d7943ea642e763f0dd45cd5f25a107f327747626f67bbcb4f37b0",
 "yunshe":"5058d34756fe52b5d635772fe6c930138692eca4d265433237d31daf1a516238",
}
def digest(apk:Path)->str:
    with zipfile.ZipFile(apk) as z:
        rows=[x for x in z.infolist() if not x.is_dir() and x.filename.replace("\\","/").lower()=="assets/lib.so"]
        if len(rows)!=1: raise RuntimeError(f"canonical assets/lib.so count={len(rows)}")
        return hashlib.sha256(z.read(rows[0])).hexdigest()
def one(label:str,apk:Path,root:Path,full:bool)->dict:
    work=root/label; work.mkdir(parents=True,exist_ok=True)
    norm=work/'normalized.apk'; restore=build_normalized_apk(apk,norm)
    got=digest(norm)
    if got!=EXPECTED[label]: raise RuntimeError(f"{label}: lib digest {got} != {EXPECTED[label]}")
    profile=resolve_profile(norm)
    if not profile: raise RuntimeError(f"{label}: profile not resolved")
    row={"label":label,"algorithm":restore.get("algorithm"),"nested":restore.get("nested_algorithm"),"canonical_lib_sha256":got,"profile":profile.get("id")}
    if full:
        out=work/'out'
        cmd=[sys.executable,str(HERE/'v3_entry.py'),'--apk',str(apk),'--outdir',str(out),'--anti-encrypted-sample','--skip-anti-resources','--threads','4']
        proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=600)
        (work/'full.log').write_text(proc.stdout,'utf-8')
        sources=[p for p in (out/'src').rglob('*') if p.is_file() and p.suffix.lower() in {'.iyu','.myu','.java'}]
        row.update(exit_code=proc.returncode,real_source_files=len(sources),has_mian=any(p.name.lower() in ('mian.iyu','main.iyu') for p in sources))
        if proc.returncode or not row['has_mian']: raise RuntimeError(f"{label}: full decrypt failed; see {work/'full.log'}")
    return row
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--shishe',type=Path); ap.add_argument('--yunshe',type=Path); ap.add_argument('--full',action='store_true'); ap.add_argument('--keep',type=Path); a=ap.parse_args()
    samples=[]
    if a.shishe: samples.append(('shishe',a.shishe.resolve()))
    if a.yunshe: samples.append(('yunshe',a.yunshe.resolve()))
    if not samples: ap.error('provide --shishe and/or --yunshe')
    root=a.keep.resolve() if a.keep else Path(tempfile.mkdtemp(prefix='iapt-v2-selftest-'))
    root.mkdir(parents=True,exist_ok=True)
    try:
        rows=[one(label,path,root,a.full) for label,path in samples]
        print(json.dumps({"ok":True,"results":rows},ensure_ascii=False,indent=2)); return 0
    finally:
        if not a.keep: shutil.rmtree(root,ignore_errors=True)
if __name__=='__main__': raise SystemExit(main())
