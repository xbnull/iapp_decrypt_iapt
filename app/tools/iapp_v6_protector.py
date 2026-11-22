#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static resolver for LianYi/NB V6 reflection dispatch wrappers.

This module is deliberately conservative.  It only replaces a wrapper when the
switch case and target metadata are recovered from the same DEX.  Constant
string decryptors are executed by the bundled tiny DEX VM; unresolved calls are
left untouched.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from . import iapp_static_dex_restore as _restore
except Exception:
    try:
        import iapp_static_dex_restore as _restore
    except Exception:
        _restore = None


def _sn(x: int, bits: int) -> int:
    x &= (1 << bits) - 1
    return x - (1 << bits) if x & (1 << (bits - 1)) else x


def _split_args(s: str) -> List[str]:
    out: List[str] = []
    start = 0
    level = 0
    quote = ''
    esc = False
    for i, ch in enumerate(s):
        if quote:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch in '([{':
            level += 1
        elif ch in ')]}':
            level = max(0, level - 1)
        elif ch == ',' and level == 0:
            out.append(s[start:i].strip())
            start = i + 1
    tail = s[start:].strip()
    if tail or s.strip():
        out.append(tail)
    return out


def _quote(s: str) -> str:
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n') + '"'


@dataclass
class _Arr:
    typ: str
    length: Any
    items: Dict[Any, Any] = field(default_factory=dict)

    def as_list(self) -> Optional[List[Any]]:
        if not isinstance(self.length, int) or self.length < 0 or self.length > 200000:
            return None
        return [self.items.get(i) for i in range(self.length)]


@dataclass
class _Obj:
    typ: str
    value: Any = None


@dataclass
class _Class:
    name: Any


@dataclass
class _Param:
    idx: int
    desc: str


@dataclass
class _Target:
    cls: Any
    name: Any
    ret: Any
    params: List[Any]
    kind: str = 'unknown'
    is_static: bool = False
    desc_cls: str = ''


@dataclass
class _Resolved:
    text: str
    value: Any = None
    side_effect: bool = False
    target: Optional[_Target] = None
    used: bool = False


class ProtectorResolver:
    """Resolve generated ``LianYi.NB.*.n(code, ...)`` calls."""

    VERSION = 'v6-protector-20260711.1'

    def __init__(self, dex: Any):
        self.dex = dex
        self.data = dex.data
        self.helper_desc = self._find_helper_class()
        self._maps: Dict[Tuple[str, int, int], Optional[_Target]] = {}
        self._switch: Dict[Tuple[str, int], Any] = {}
        self._statics: Dict[str, Dict[str, Any]] = {}
        self._field_index: Dict[Tuple[str, str], Any] = {(f.cls, f.name): f for f in dex.fields}
        self._method_impl: Dict[Tuple[str, str, Tuple[str, ...]], Any] = {}
        for cls in dex.classes:
            try:
                for em in dex.class_methods(cls):
                    m = dex.methods[em.method_idx]
                    self._method_impl[(cls, m.name, tuple(m.proto.params))] = (m, em)
            except Exception:
                pass
        self.vm = None
        if _restore is not None:
            try:
                d = _restore.DexFile(self.data)
                self.vm = _restore.DexVM([d])
            except Exception:
                self.vm = None
        self.stats = {'calls_seen': 0, 'calls_resolved': 0, 'strings_decrypted': 0, 'targets_recovered': 0}
        self._current_candidates: List[_Resolved] = []
        self._constant_cache: Dict[Tuple[str, int], Any] = {}

    def _find_helper_class(self) -> str:
        # Central helper has many overloaded methods and a short[] field named '$'.
        for cls in self.dex.classes:
            if not cls.startswith('LLianYi/NB/'):
                continue
            fields = [f for f in self.dex.fields if f.cls == cls]
            methods = []
            try:
                methods = [self.dex.methods[e.method_idx] for e in self.dex.class_methods(cls)]
            except Exception:
                pass
            if any(f.name == '$' and f.typ == '[S' for f in fields) and len(methods) > 15:
                return cls
        return 'LLianYi/NB/ۣۡ۟ۤ;'

    @staticmethod
    def _desc(human: str) -> str:
        if not isinstance(human, str):
            return ''
        if human.startswith('L') and human.endswith(';'):
            return human
        if human.startswith('['):
            return human
        return 'L' + human.replace('.', '/') + ';'

    @staticmethod
    def _human(desc: str) -> str:
        if not isinstance(desc, str):
            return str(desc)
        if desc.startswith('L') and desc.endswith(';'):
            return desc[1:-1].replace('/', '.')
        return desc

    @staticmethod
    def _regs35(aa: int, w2: int) -> List[int]:
        count = (aa >> 4) & 0x0F
        g = aa & 0x0F
        c = w2 & 0x0F
        d = (w2 >> 4) & 0x0F
        e = (w2 >> 8) & 0x0F
        f = (w2 >> 12) & 0x0F
        return [c, d, e, f, g][:count]

    def _ilen(self, op: int) -> int:
        if op in {0x00,0x01,0x04,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x1d,0x1e,0x27,0x28,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c}:
            return 1
        if op in set(range(0x02,0x09)) | {0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x21,0x22,0x23,0x29} | set(range(0x2d,0x3e)) | set(range(0x44,0x6e)) | set(range(0xd0,0xe3)):
            return 2
        if op in {0x03,0x09,0x14,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c} | set(range(0x6e,0x79)) | set(range(0x90,0xb0)):
            return 3
        if op == 0x18:
            return 5
        return 1

    def _fill_payload(self, cu: List[int], pos: int) -> Optional[List[int]]:
        if pos < 0 or pos + 4 > len(cu) or cu[pos] != 0x0300:
            return None
        width = cu[pos + 1]
        size = cu[pos + 2] | (cu[pos + 3] << 16)
        raw = bytearray()
        for w in cu[pos + 4:]:
            raw.extend((w & 0xff, (w >> 8) & 0xff))
            if len(raw) >= width * size:
                break
        out = []
        for i in range(size):
            chunk = bytes(raw[i * width:(i + 1) * width])
            out.append(int.from_bytes(chunk, 'little', signed=width in (1,2,4,8)))
        return out

    def _class_statics(self, cls: str) -> Dict[str, Any]:
        if cls in self._statics:
            return self._statics[cls]
        out: Dict[str, Any] = {}
        # Encoded static values.
        try:
            for idx, val in self.dex.static_values(cls).items():
                out[self.dex.fields[idx].name] = val
        except Exception:
            pass
        # Arrays initialized by <clinit>.
        try:
            em = next((e for e in self.dex.class_methods(cls) if self.dex.methods[e.method_idx].name == '<clinit>'), None)
            if em and em.code_off:
                _, _, cu = self.dex.code_units(em.code_off)
                regs: Dict[int, Any] = {}
                pc = 0
                while pc < len(cu):
                    w = cu[pc]; op = w & 0xff; aa = w >> 8
                    if op == 0x12:
                        regs[aa & 0xf] = _sn(aa >> 4, 4)
                    elif op == 0x13:
                        regs[aa] = _sn(cu[pc + 1], 16)
                    elif op == 0x14:
                        regs[aa] = _sn(cu[pc + 1] | (cu[pc + 2] << 16), 32)
                    elif op == 0x23:
                        a, b = aa & 0xf, aa >> 4
                        regs[a] = _Arr(self.dex.types[cu[pc + 1]], regs.get(b))
                    elif op == 0x26:
                        off = _sn(cu[pc + 1] | (cu[pc + 2] << 16), 32)
                        vals = self._fill_payload(cu, pc + off)
                        arr = regs.get(aa)
                        if isinstance(arr, _Arr) and vals is not None:
                            arr.items.update({i: x for i, x in enumerate(vals)})
                    elif op in (0x01,0x04,0x07):
                        regs[aa & 0xf] = regs.get(aa >> 4)
                    elif op in (0x02,0x05,0x08):
                        regs[aa] = regs.get(cu[pc + 1])
                    elif op in (0x03,0x06,0x09):
                        regs[aa] = regs.get(cu[pc + 1] | (cu[pc + 2] << 16))
                    elif 0x67 <= op <= 0x6d:
                        fr = self.dex.fields[cu[pc + 1]]
                        out[fr.name] = regs.get(aa)
                    pc += self._ilen(op)
        except Exception:
            pass
        self._statics[cls] = out
        return out

    def _switch_info(self, wrapper: str, arity: int):
        ck = (wrapper, arity)
        if ck in self._switch:
            return self._switch[ck]
        em = None
        try:
            for x in self.dex.class_methods(wrapper):
                m = self.dex.methods[x.method_idx]
                if m.name == 'n' and len(m.proto.params) == arity:
                    em = x; break
        except Exception:
            pass
        if not em or not em.code_off:
            self._switch[ck] = None
            return None
        regs_count, ins_count, cu = self.dex.code_units(em.code_off)
        regs: Dict[int, Any] = {}
        pbase = regs_count - ins_count
        m = self.dex.methods[em.method_idx]
        for j, p in enumerate(m.proto.params):
            regs[pbase + j] = _Param(j, p)
        xor_key = 0
        pc = 0
        cases = None
        while pc < min(len(cu), 256):
            w = cu[pc]; op = w & 0xff; aa = w >> 8
            if op == 0x12:
                regs[aa & 0xf] = _sn(aa >> 4, 4)
            elif op == 0x13:
                regs[aa] = _sn(cu[pc + 1], 16)
            elif op == 0x14:
                regs[aa] = _sn(cu[pc + 1] | (cu[pc + 2] << 16), 32)
            elif op in (0x01,0x04,0x07):
                regs[aa & 0xf] = regs.get(aa >> 4)
            elif op in (0x02,0x05,0x08):
                regs[aa] = regs.get(cu[pc + 1])
            elif op == 0xb7:
                a, b = aa & 0xf, aa >> 4
                va, vb = regs.get(a), regs.get(b)
                if isinstance(va, int) and isinstance(vb, _Param):
                    xor_key = va
                elif isinstance(vb, int) and isinstance(va, _Param):
                    xor_key = vb
            elif op in (0x2b, 0x2c):
                off = _sn(cu[pc + 1] | (cu[pc + 2] << 16), 32)
                payload = pc + off
                if payload < 0 or payload + 2 > len(cu):
                    break
                ident, size = cu[payload], cu[payload + 1]
                if ident == 0x0200:
                    pos = payload + 2
                    keys = [_sn(cu[pos + 2*j] | (cu[pos + 2*j + 1] << 16), 32) for j in range(size)]
                    pos += size * 2
                elif ident == 0x0100:
                    first = _sn(cu[payload + 2] | (cu[payload + 3] << 16), 32)
                    keys = list(range(first, first + size))
                    pos = payload + 4
                else:
                    break
                tgts = [_sn(cu[pos + 2*j] | (cu[pos + 2*j + 1] << 16), 32) for j in range(size)]
                cases = {k: pc + t for k, t in zip(keys, tgts)}
                break
            pc += self._ilen(op)
        result = (em, cu, regs_count, ins_count, xor_key, cases or {})
        self._switch[ck] = result
        return result

    @staticmethod
    def _str(v: Any) -> Any:
        if isinstance(v, _Obj) and v.typ == 'Ljava/lang/String;':
            return v.value
        if isinstance(v, _Class):
            return v.name
        return v

    def _invoke_sym(self, m: Any, args: List[Any], calls: List[Any]) -> Any:
        if m.name == '<init>' and args and isinstance(args[0], _Obj):
            obj = args[0]
            if m.cls == 'Ljava/lang/String;' and len(args) > 1:
                src = args[1]
                if isinstance(src, _Arr):
                    vals = src.as_list()
                    if vals is not None and all(isinstance(x, int) for x in vals):
                        raw = bytes(int(x) & 0xff for x in vals)
                        for enc in ('utf-8','gb18030','latin1'):
                            try:
                                obj.value = raw.decode(enc); break
                            except Exception:
                                pass
            return None
        vals = [self._str(x) for x in args]
        if m.cls == self.helper_desc:
            p = m.proto.params
            if p == ['Ljava/lang/String;'] and m.proto.ret == 'Ljava/lang/Class;':
                return _Class(vals[0])
            if m.proto.ret == 'Ljava/lang/Object;' and len(p) in (3,4) and p[0] in ('Ljava/lang/String;','Ljava/lang/Class;') and p[1:3] == ['Ljava/lang/String;','Ljava/lang/String;']:
                c = vals[0].name if isinstance(vals[0], _Class) else vals[0]
                ps = vals[3] if len(vals) > 3 else []
                if isinstance(ps, _Arr):
                    ps = ps.as_list() or []
                ps = [self._str(x) for x in (ps or [])]
                t = _Target(c, vals[1], vals[2], ps)
                calls.append(t)
                return t
        return ('call', m.cls, m.name, args)

    def _classify(self, t: _Target) -> _Target:
        t.desc_cls = self._desc(str(t.cls))
        fr = self._field_index.get((t.desc_cls, str(t.name)))
        if fr is not None and not t.params:
            t.kind = 'field'
            # Static-ness is inferred from class static field list.
            try:
                t.is_static = any(self.dex.fields[i].name == fr.name for i in self.dex.class_static_field_indices(t.desc_cls))
            except Exception:
                t.is_static = False
            return t
        key = (t.desc_cls, str(t.name), tuple(self._desc_param(x) for x in t.params))
        pair = self._method_impl.get(key)
        if pair:
            _, em = pair
            t.kind = 'method'
            t.is_static = bool(em.access & 0x0008)
        return t

    @staticmethod
    def _desc_param(x: Any) -> str:
        x = str(x)
        prim = {'void':'V','boolean':'Z','byte':'B','short':'S','char':'C','int':'I','long':'J','float':'F','double':'D'}
        if x in prim: return prim[x]
        if x.startswith('['): return x.replace('.', '/')
        if x.endswith('[]'):
            return '[' + ProtectorResolver._desc_param(x[:-2])
        if x.startswith('L') and x.endswith(';'): return x
        return 'L' + x.replace('.', '/') + ';'

    def target(self, wrapper: str, code: int, arity: int) -> Optional[_Target]:
        key = (wrapper, int(code), int(arity))
        if key in self._maps:
            return self._maps[key]
        info = self._switch_info(wrapper, arity)
        if not info:
            self._maps[key] = None; return None
        em, cu, regs_count, ins_count, xor_key, cases = info
        start = cases.get(int(code) ^ int(xor_key))
        if start is None:
            self._maps[key] = None; return None
        m = self.dex.methods[em.method_idx]
        regs: Dict[int, Any] = {}
        pbase = regs_count - ins_count
        for j, p in enumerate(m.proto.params):
            regs[pbase + j] = int(code) if j == 0 else _Param(j, p)
        pending = None
        calls: List[_Target] = []
        pc = start
        seen: Dict[int,int] = {}
        steps = 0
        while 0 <= pc < len(cu) and steps < 2500:
            steps += 1
            seen[pc] = seen.get(pc, 0) + 1
            if seen[pc] > 4:
                break
            w = cu[pc]; op = w & 0xff; aa = w >> 8
            nxt = pc + self._ilen(op)
            try:
                if op == 0x12: regs[aa & 0xf] = _sn(aa >> 4, 4)
                elif op == 0x13: regs[aa] = _sn(cu[pc + 1], 16)
                elif op == 0x14: regs[aa] = _sn(cu[pc + 1] | (cu[pc + 2] << 16), 32)
                elif op == 0x15: regs[aa] = _sn(cu[pc + 1] << 16, 32)
                elif op == 0x16: regs[aa] = _sn(cu[pc + 1], 16)
                elif op == 0x1a: regs[aa] = self.dex.strings[cu[pc + 1]]
                elif op == 0x1b: regs[aa] = self.dex.strings[cu[pc + 1] | (cu[pc + 2] << 16)]
                elif op == 0x1c: regs[aa] = _Class(self.dex.types[cu[pc + 1]])
                elif op == 0x22: regs[aa] = _Obj(self.dex.types[cu[pc + 1]])
                elif op == 0x23:
                    a,b = aa & 0xf, aa >> 4
                    regs[a] = _Arr(self.dex.types[cu[pc + 1]], regs.get(b))
                elif op == 0x24:
                    rr = self._regs35(aa, cu[pc + 2])
                    regs_arr = _Arr(self.dex.types[cu[pc + 1]], len(rr), {i: regs.get(r) for i,r in enumerate(rr)})
                    pending = regs_arr
                elif op == 0x25:
                    count,start_r = aa,cu[pc + 2]
                    pending = _Arr(self.dex.types[cu[pc + 1]], count, {i:regs.get(start_r+i) for i in range(count)})
                elif op == 0x26:
                    off = _sn(cu[pc + 1] | (cu[pc + 2] << 16), 32)
                    vals = self._fill_payload(cu, pc + off)
                    arr = regs.get(aa)
                    if isinstance(arr, _Arr) and vals is not None: arr.items.update({i:x for i,x in enumerate(vals)})
                elif op in (0x01,0x04,0x07): regs[aa & 0xf] = regs.get(aa >> 4)
                elif op in (0x02,0x05,0x08): regs[aa] = regs.get(cu[pc + 1])
                elif op in (0x03,0x06,0x09): regs[aa] = regs.get(cu[pc + 1] | (cu[pc + 2] << 16))
                elif op in (0x0a,0x0b,0x0c): regs[aa] = pending; pending = None
                elif 0x44 <= op <= 0x4a:
                    a,b,c = aa, cu[pc + 1] & 0xff, cu[pc + 1] >> 8
                    arr, idx = regs.get(b), regs.get(c)
                    regs[a] = arr.items.get(idx) if isinstance(arr, _Arr) else None
                elif 0x4b <= op <= 0x51:
                    a,b,c = aa, cu[pc + 1] & 0xff, cu[pc + 1] >> 8
                    arr, idx = regs.get(b), regs.get(c)
                    if isinstance(arr, _Arr): arr.items[idx] = regs.get(a)
                elif 0x60 <= op <= 0x66:
                    fr = self.dex.fields[cu[pc + 1]]
                    regs[aa] = self._class_statics(fr.cls).get(fr.name)
                elif 0x6e <= op <= 0x72:
                    im = self.dex.methods[cu[pc + 1]]
                    rr = self._regs35(aa, cu[pc + 2])
                    pending = self._invoke_sym(im, [regs.get(r) for r in rr], calls)
                elif 0x74 <= op <= 0x78:
                    im = self.dex.methods[cu[pc + 1]]
                    pending = self._invoke_sym(im, [regs.get(r) for r in range(cu[pc + 2], cu[pc + 2] + aa)], calls)
                elif op == 0x8d:
                    a,b = aa & 0xf, aa >> 4; x = regs.get(b)
                    regs[a] = _sn(x,8) if isinstance(x,int) else x
                elif op == 0x8f:
                    a,b = aa & 0xf, aa >> 4; x = regs.get(b)
                    regs[a] = _sn(x,16) if isinstance(x,int) else x
                elif op == 0xb7:
                    a,b = aa & 0xf, aa >> 4; x,y = regs.get(a),regs.get(b)
                    if isinstance(x,int) and isinstance(y,int): regs[a] = x ^ y
                elif op in (0x28,0x29,0x2a):
                    off = _sn(aa,8) if op == 0x28 else (_sn(cu[pc + 1],16) if op == 0x29 else _sn(cu[pc + 1] | (cu[pc + 2] << 16),32))
                    nxt = pc + off
                elif 0x32 <= op <= 0x37:
                    a,b,off = aa & 0xf, aa >> 4, _sn(cu[pc + 1],16)
                    x,y = regs.get(a),regs.get(b)
                    if isinstance(x,(int,bool)) and isinstance(y,(int,bool)):
                        cond = [x==y,x!=y,x<y,x>=y,x>y,x<=y][op-0x32]
                        if cond: nxt = pc + off
                elif 0x38 <= op <= 0x3d:
                    off,x = _sn(cu[pc + 1],16),regs.get(aa)
                    if isinstance(x,(int,bool)) or x is None:
                        xx = 0 if x is None else x
                        cond = [xx==0,xx!=0,xx<0,xx>=0,xx>0,xx<=0][op-0x38]
                        if cond: nxt = pc + off
                elif op in (0x0e,0x0f,0x10,0x11):
                    break
            except Exception:
                pass
            pc = nxt
        target = self._classify(calls[-1]) if calls else None
        if target:
            self.stats['targets_recovered'] += 1
        self._maps[key] = target
        return target

    def _field_value(self, t: _Target, receiver: Any = None) -> Any:
        if t.kind != 'field':
            return None
        return self._class_statics(t.desc_cls).get(str(t.name)) if t.is_static else None

    def _vm_call(self, t: _Target, args: List[Any]) -> Any:
        if self.vm is None or t.kind != 'method' or not t.is_static:
            return None
        vals = []
        for x in args:
            if isinstance(x, _Arr):
                x = x.as_list()
            if isinstance(x, _Resolved):
                x = x.value
            if isinstance(x, _Obj):
                x = x.value
            if x is None:
                return None
            vals.append(x)
        try:
            result = self.vm.call(t.desc_cls, str(t.name), [self._desc_param(x) for x in t.params], vals)
            if hasattr(result, 'value'):
                result = result.value
            return result
        except Exception:
            return None

    def _render_target(self, t: _Target, receiver: _Resolved, args: List[_Resolved]) -> _Resolved:
        raw_args = [x.value if x.value is not None else x.text for x in args]
        if t.kind == 'field':
            value = self._field_value(t, receiver.value)
            if value is not None:
                return _Resolved(f'{t.cls}.{t.name}', value, target=t)
            base = str(t.cls) if t.is_static else receiver.text
            if str(t.cls).startswith('com.iApp.protection.LianYi.') and receiver.text in ('this','0','null'):
                return _Resolved(str(t.name), target=t)
            return _Resolved(f'{base}.{t.name}', target=t)
        const = self._vm_call(t, raw_args)
        if isinstance(const, str):
            self.stats['strings_decrypted'] += 1
            return _Resolved(_quote(const), const, target=t)
        if isinstance(const, (int,bool)):
            return _Resolved(str(const).lower() if isinstance(const,bool) else str(const), const, target=t)
        texts = [x.text for x in args]
        page = str(t.cls).startswith('com.iApp.protection.LianYi.')
        if t.is_static:
            call = f'{t.cls}.{t.name}(' + ','.join(texts) + ')'
        elif page and receiver.text in ('this','0','null'):
            call = f'this.{t.name}(' + ','.join(texts) + ')'
        else:
            call = f'{receiver.text}.{t.name}(' + ','.join(texts) + ')'
        # This call consumes its receiver/arguments.  Tracking that relation lets
        # rewrite_lines emit only the outermost discarded expression instead of
        # either losing the whole call chain or duplicating every getter.
        receiver.used = True
        for item in args:
            item.used = True
        # Only page/iApp methods and confirmed void methods are standalone
        # statements.  Obfuscated helper methods that merely decrypt/compute a
        # value must not leak into output when their value is unused.
        name = str(t.name)
        # Page helpers mix getters and commands.  Treating every page method as
        # a side effect used to emit noise such as activity(), st(), zf(), cls()
        # as standalone statements.  Keep only confirmed commands/mutators.
        page_effect_names = {
            'tw','t','ufnsui','uigo','us','syso','java','javax','stop','end',
            'dh','bfm','hw','ushsp','ula','ufnsui','uall','uapp','uht','ufnsui'
        }
        overloaded_setters = {'s','ss','sss'}
        widget_mutator = (
            str(t.desc_cls).startswith('Li6/runlibrary/app/v/')
            and len(args) >= 1
            and name not in {'text','id','width','height','st'}  # zero-arg getter overloads are filtered by len(args)
        )
        # width(value), text(value), id(value), etc. are setters despite sharing
        # names with zero-argument getters.  Argument count disambiguates them.
        if str(t.desc_cls).startswith('Li6/runlibrary/app/v/') and len(args) >= 1:
            widget_mutator = True
        has_effect = (
            str(t.ret) in ('void','V')
            or name in page_effect_names
            or (name in overloaded_setters and len(args) >= 2)
            or widget_mutator
            or (not page and (name.startswith('set') or name.startswith('add') or name in {'put','start','show','dismiss','write','close','delete','mkdirs','renameTo'}))
        )
        result = _Resolved(call, side_effect=has_effect, target=t)
        if has_effect:
            self._current_candidates.append(result)
        return result

    def _eval_atom(self, expr: str, env: Dict[str,_Resolved], arrays: Dict[str,_Arr]) -> _Resolved:
        e = expr.strip()
        # Strip a cast only when it wraps the complete wrapper call.  Do not
        # eat the left side of expressions such as (((HashMap) n(...)) ^ key).
        for _ in range(3):
            m = re.match(r'^\(\([^()]+\)\s*', e)
            if m and e.endswith(')'):
                candidate = e[m.end():-1].strip()
                if candidate.startswith('LianYi.NB.') and candidate.count('(') == candidate.count(')'):
                    e = candidate
                    continue
            m = re.match(r'^\([^()]+\)\s*', e)
            if m:
                candidate = e[m.end():].strip()
                if candidate.startswith('LianYi.NB.') and candidate.count('(') == candidate.count(')'):
                    e = candidate
                    continue
            break
        e = re.sub(r'\.intValue\(\)$', '', e)
        if e in env:
            env[e].used = True
            return env[e]
        if e in arrays: return _Resolved(e, arrays[e])
        if re.fullmatch(r'-?\d+', e): return _Resolved(e, int(e))
        if e in ('null','0'): return _Resolved(e, None if e=='null' else 0)
        if e in ('true','false'): return _Resolved(e, e=='true')
        if len(e)>=2 and e[0]==e[-1]=='"':
            try:
                import json
                return _Resolved(e, json.loads(e))
            except Exception:
                return _Resolved(e, e[1:-1])
        # Resolve wrappers anywhere in expression, then keep surrounding syntax.
        rewritten, resolved = self._rewrite_expr(e, env, arrays)
        if resolved is not None and rewritten == resolved.text:
            return resolved
        return _Resolved(rewritten)

    def _wrapper_span(self, text: str) -> Optional[Tuple[int,int,str,str]]:
        # Return innermost/leftmost wrapper call.
        pat = re.compile(r'LianYi\.NB\.([^\.\s()]+)\.n\(')
        found = None
        for m in pat.finditer(text):
            start_paren = m.end() - 1
            depth = 0; quote=''; esc=False
            for i in range(start_paren, len(text)):
                ch=text[i]
                if quote:
                    if esc: esc=False
                    elif ch=='\\': esc=True
                    elif ch==quote: quote=''
                    continue
                if ch in ('"',"'"): quote=ch
                elif ch=='(': depth+=1
                elif ch==')':
                    depth-=1
                    if depth==0:
                        found=(m.start(),i+1,m.group(1),text[start_paren+1:i])
                        break
            if found:
                # continue looking for a nested wrapper inside arguments first
                nested=self._wrapper_span(found[3])
                if nested:
                    ns,ne,nc,na=nested
                    base=start_paren+1
                    return (base+ns,base+ne,nc,na)
                return found
        return None

    def _constant_wrapper(self, wrapper: str, code: int) -> Optional[_Resolved]:
        """Execute a one-argument generated constant/string wrapper in the VM.

        These n(int) methods are not reflection dispatchers: each switch case
        constructs a literal byte array, caches it in p1/p2/p3, and returns the
        String/Object.  The VM models that cache and is only used with a concrete
        integer argument, so no application code or Android API is executed.
        """
        key = (wrapper, int(code))
        if key in self._constant_cache:
            value = self._constant_cache[key]
        else:
            value = None
            if self.vm is not None:
                try:
                    value = self.vm.call(self._human(wrapper), 'n', ['int'], [int(code)])
                except Exception:
                    value = None
            self._constant_cache[key] = value
        if isinstance(value, str):
            self.stats['strings_decrypted'] += 1
            return _Resolved(_quote(value), value)
        if isinstance(value, bool):
            return _Resolved('true' if value else 'false', value)
        if isinstance(value, int):
            return _Resolved(str(value), value)
        return None

    def _rewrite_expr(self, expr: str, env: Dict[str,_Resolved], arrays: Dict[str,_Arr]) -> Tuple[str,Optional[_Resolved]]:
        text=expr
        last_res=None
        for _ in range(30):
            span=self._wrapper_span(text)
            if not span: break
            s,e,short,args_text=span
            parts=_split_args(args_text)
            if not parts: break
            try: code=int(parts[0].strip())
            except Exception: break
            arity=len(parts)
            wrapper='LLianYi/NB/'+short+';'
            self.stats['calls_seen']+=1
            target=self.target(wrapper,code,arity)
            if target is None:
                if arity == 1:
                    const_res = self._constant_wrapper(wrapper, code)
                    if const_res is not None:
                        before, after = text[:s], text[e:]
                        if before.strip() or after.strip():
                            const_res.used = True
                        text = before + const_res.text + after
                        last_res = const_res
                        self.stats['calls_resolved'] += 1
                        continue
                break
            receiver=_Resolved('null',None)
            actual:List[_Resolved]=[]
            if arity>=2:
                receiver=self._eval_atom(parts[1],env,arrays)
            if arity>=3:
                av=self._eval_atom(parts[2],env,arrays)
                arr=av.value
                if isinstance(arr,_Arr):
                    lst=arr.as_list() or []
                    actual=[x if isinstance(x,_Resolved) else self._value_resolved(x) for x in lst]
                    for item in actual:
                        item.used = True
                else:
                    actual=[av]
            result=self._render_target(target,receiver,actual)
            before, after = text[:s], text[e:]
            # Casts/boxing and conditions consume the result; a bare call does not.
            if before.strip() or after.strip():
                result.used = True
            text=before+result.text+after
            last_res=result
            self.stats['calls_resolved']+=1
        text=re.sub(r'\(\((?:Integer|Boolean|String|Activity|Object|short\[\]|HashMap|[\w.$\[\]]+)\)\s*([^()]+)\)\.intValue\(\)',r'\1',text)
        return text,last_res

    def _value_resolved(self,x:Any)->_Resolved:
        if isinstance(x,_Resolved): return x
        if isinstance(x,_Arr): return _Resolved('/*array*/',x)
        if isinstance(x,str):
            if x.startswith('"') and x.endswith('"'): return _Resolved(x,x[1:-1])
            return _Resolved(x,x)
        if x is None: return _Resolved('null',None)
        return _Resolved(str(x),x)

    def rewrite_lines(self, lines: List[str]) -> List[str]:
        env: Dict[str,_Resolved] = {}
        arrays: Dict[str,_Arr] = {}
        out: List[str] = []
        last_side_effect_canon = ''
        self._current_candidates = []
        temp_re = re.compile(r'^v\d+(?:_(?:arr|obj|len)_\d+)?$')
        for raw in lines:
            line=raw.strip()
            marker = None
            if line.startswith('// IAPT_DISCARDED_CALL '):
                marker = 'discarded'
                line = line[len('// IAPT_DISCARDED_CALL '):].strip()
            elif line.startswith('// IAPT_MAYBE_CALL '):
                marker = 'maybe'
                line = line[len('// IAPT_MAYBE_CALL '):].strip()
            # Array declaration from pseudo_event_method.
            m=re.match(r'^[\w.$]+\[\]\s+(v\d+_arr_\d+)\s*=\s*new\s+[\w.$]+\[([^]]+)\];$',line)
            if m:
                ln=self._eval_atom(m.group(2),env,arrays).value
                arrays[m.group(1)]=_Arr('[]',ln if isinstance(ln,int) else 0)
                continue
            # Array element assignment.
            m=re.match(r'^(v\d+_arr_\d+)\[([^]]+)\]\s*=\s*(.+);$',line)
            if m and m.group(1) in arrays:
                idxr=self._eval_atom(m.group(2),env,arrays)
                val=self._eval_atom(m.group(3),env,arrays)
                idx=idxr.value if isinstance(idxr.value,int) else len(arrays[m.group(1)].items)
                arrays[m.group(1)].items[idx]=val
                continue
            if marker is not None:
                expr = line[:-1].strip() if line.endswith(';') else line
                cand_start = len(self._current_candidates)
                rewritten, res = self._rewrite_expr(expr, env, arrays)
                # A resolved wrapper carries the real target's side-effect bit.
                # For direct calls keep only known iApp/UI/collection/thread
                # mutators; boxing/getters are intentionally dropped.
                direct_effect = bool(re.search(
                    r'(?:^|\.)((?:add|put|set[A-Z]\w*|start|run|show|dismiss|send|write|close|delete|mkdirs|renameTo|java|javax|tw|t|uigo|ufnsui|us|ug|s|ss|sss|syso|cls|javanew|stop|end|dh|hw|ushsp|ngde))\s*\(',
                    rewritten
                ))
                if (res is not None and res.side_effect) or direct_effect:
                    stmt = rewritten.rstrip(';').strip()
                    # Collapse boxing/cast wrappers around the real side-effect call.
                    for _ in range(4):
                        mbox = re.match(r'^\(\((?:Boolean|Integer|Object)\)\s*(.*)\)\.(?:booleanValue|intValue)\(\)$', stmt, re.S)
                        if not mbox:
                            break
                        stmt = mbox.group(1).strip()
                    stmt = stmt.rstrip(';') + ';'
                    canon = re.sub(r'\s+', '', stmt)
                    if canon != last_side_effect_canon:
                        out.append('// IAPT_SIDE_EFFECT ' + stmt)
                        last_side_effect_canon = canon
                # Marker handling already decided whether this expression is a
                # top-level statement; suppress candidate re-emission below.
                for cand in self._current_candidates[cand_start:]:
                    cand.used = True
                continue
            # Temporary declaration/assignment.
            m=re.match(r'^(?:[\w.$<>\[\]]+\s+)?(v\d+(?:_obj_\d+)?)\s*=\s*(.+);$',line)
            if m:
                name,rhs=m.group(1),m.group(2)
                res=self._eval_atom(rhs,env,arrays)
                env[name]=res
                # Emit confirmed side-effect calls; suppress compiler scaffolding.
                if res.side_effect and res.target and str(res.target.ret) in ('void','V'):
                    out.append(res.text+';')
                continue
            rewritten,res=self._rewrite_expr(line,env,arrays)
            # Drop pure control-flow scaffolding after successful resolution.
            if rewritten.startswith('// goto'):
                continue
            # Remove redundant casts/boxing around now-readable expressions.
            rewritten=re.sub(r'\(\((?:Integer|Boolean|String|Activity|Object|short\[\]|HashMap|[\w.$\[\]]+)\)\s*([^()]+)\)\.intValue\(\)',r'\1',rewritten)
            # Never emit syntactically broken text when a deeply nested cast was
            # only partially understood.  Preserve it as a diagnostic comment.
            if rewritten.count('(') != rewritten.count(')'):
                rewritten = '// IAPT高级分析未解释: ' + rewritten[:220]
            out.append(rewritten)
        # Emit only calls whose return value was never consumed by another
        # recovered call/expression.  These are the actual top-level statements.
        seen_text = {re.sub(r'\s+', '', x.replace('// IAPT_SIDE_EFFECT ', '')) for x in out}
        for cand in self._current_candidates:
            if cand.side_effect and not cand.used:
                stmt = cand.text.rstrip(';') + ';'
                canon = re.sub(r'\s+', '', stmt)
                if canon not in seen_text:
                    out.append('// IAPT_SIDE_EFFECT ' + stmt)
                    seen_text.add(canon)
        return out
