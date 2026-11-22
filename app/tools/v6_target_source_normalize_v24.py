#!/usr/bin/env python3
from pathlib import Path
import re, xml.etree.ElementTree as ET

CODE_ASSIGN = re.compile(r'(?m)^(\s*)(?:gd\s+)?s\s+([A-Za-z_]\w*)\s*=\s*json\(([^\n]+),"get","code"\)\s*$')
SCANNER_ASSIGN = re.compile(r'(?m)^(\s*)s\s+scanner_rows\s*=\s*javax\(null,scanner_cls,"scan",scanner_args\)\s*$')

def _escape_multiline_strings(text: str):
    out=[]; i=0; inside=False; esc=False; n=0
    while i < len(text):
        ch=text[i]
        if ch in '\r\n':
            step=2 if ch=='\r' and i+1<len(text) and text[i+1]=='\n' else 1
            if inside:
                out.append('\\n'); n+=1; i+=step
                while i<len(text) and text[i] in ' \t': i+=1
                esc=False; continue
            out.append('\n'); i+=step; esc=False; continue
        out.append(ch)
        if inside:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': inside=False
        elif ch=='"': inside=True; esc=False
        i+=1
    return ''.join(out),n

def _find_multiline_strings(text: str):
    inside=False; esc=False; hits=0
    for ch in text:
        if ch in '\r\n':
            if inside: hits+=1
            esc=False; continue
        if inside:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': inside=False
        elif ch=='"': inside=True; esc=False
    return hits

def _fix_text(text: str):
    count=0
    def repl(m):
        nonlocal count
        count+=1
        return f'{m.group(1)}s {m.group(2)}=""+json({m.group(3)},"get","code")'
    text=CODE_ASSIGN.sub(repl,text)
    text,n=re.subn(r'(?m)^(\s*rg\s+([A-Za-z_]\w*(?:_code|Code|code))\s*==\s*)200(\s*\{)',r'\1"200"\3',text); count+=n
    text,n=SCANNER_ASSIGN.subn(r'\1java.util.List scanner_rows=javax(null,scanner_cls,"scan",scanner_args)',text); count+=n
    text,n=re.subn(r'(?m)^(\s*)s\s+item_ids\s*=\s*\{10006,10004,10007,10008\}',r'\1int[] item_ids={10006,10004,10007,10008}',text); count+=n
    text,n=_escape_multiline_strings(text); count+=n
    return text,count

def normalize_source_tree(src_dir: str) -> dict:
    root=Path(src_dir); changes={}; errors={}; pages=[]
    for p in sorted(root.glob('*.iyu')):
        pages.append(p)
        try:
            s=p.read_text(encoding='utf-8')
            ns,n=_fix_text(s)
            if ns!=s:
                p.write_text(ns,encoding='utf-8'); changes[p.name]=n
            ET.parse(p)
        except Exception as e: errors[p.name]=str(e)
    alltext='\n'.join(p.read_text(encoding='utf-8',errors='ignore') for p in pages)
    bad_object_codes=re.findall(r'(?m)^\s*s\s+\w*code\s*=\s*json\([^\n]+,"get","code"\)',alltext)
    bad_numeric_cmp=re.findall(r'rg\s+\w*code\s*==\s*200\s*\{',alltext)
    bad_scanner=re.findall(r'(?m)^\s*s\s+scanner_rows\s*=\s*javax\(null,scanner_cls,"scan",scanner_args\)',alltext)
    bad_multiline={p.name:_find_multiline_strings(p.read_text(encoding='utf-8',errors='ignore')) for p in pages}
    bad_multiline={k:v for k,v in bad_multiline.items() if v}
    return {
      'version':'v24-v6-string-literal-line-safe-recovery',
      'pages':len(pages),'changes':changes,'xml_errors':errors,
      'bad_object_code_assignments':bad_object_codes,
      'bad_numeric_code_comparisons':bad_numeric_cmp,
      'bad_untyped_scanner_lists':bad_scanner,
      'physical_newlines_inside_string_literals':bad_multiline,
      'ok':not errors and not bad_object_codes and not bad_numeric_cmp and not bad_scanner and not bad_multiline,
    }
