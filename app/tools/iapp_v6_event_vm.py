#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Concrete V6 event recovery for protected iApp dex files.

The normal UI recoverer can rebuild widgets from the generated builder method,
but protected event methods are control-flow flattened and their real calls are
hidden behind LianYi.NB reflection dispatch wrappers.  This module executes only
that deterministic bytecode subset, follows the actual switch path, expands
Runnable/Thread bodies and emits conservative iApp V6 source.

It is deliberately fail-closed: a call is emitted as executable V6 only when its
target and arguments are known.  Unresolved runtime-dependent work is kept in the
deep-code report and does not become malformed .iyu source.
"""
from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from . import iapp_static_dex_restore as svm
except Exception:  # direct script import
    import iapp_static_dex_restore as svm


@dataclass
class Expr:
    text: str
    typ: str = 'Ljava/lang/Object;'

    def __str__(self) -> str:
        return self.text


def java_float_bits(x: Any) -> Any:
    if isinstance(x, int):
        return struct.unpack('<f', struct.pack('<I', x & 0xffffffff))[0]
    try:
        return float(x)
    except Exception:
        return x


def java_double_bits(x: Any) -> Any:
    if isinstance(x, int):
        return struct.unpack('<d', struct.pack('<Q', x & 0xffffffffffffffff))[0]
    try:
        return float(x)
    except Exception:
        return x


def _unwrap(v: Any) -> Any:
    if isinstance(v, svm.Obj):
        if isinstance(v.value, Expr):
            return v.value
        if v.typ == 'Ljava/lang/String;':
            return '' if v.value is None else str(v.value)
        return v.value if v.value is not None else v
    return v


def render_value(v: Any) -> str:
    if isinstance(v, Expr):
        return v.text
    if isinstance(v, svm.Obj):
        if isinstance(v.value, Expr):
            return v.value.text
        if v.typ == 'Ljava/lang/String;':
            return json.dumps('' if v.value is None else str(v.value), ensure_ascii=False).replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
        cid = v.fields.get('control_id')
        if cid is not None:
            return render_value(cid)
        if isinstance(v.value, str):
            return v.value
        return 'null'
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False).replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if v is None:
        return 'null'
    if isinstance(v, float):
        if not math.isfinite(v):
            return '0'
        if abs(v - round(v)) < 1e-9:
            return str(int(round(v)))
        return ('%.8g' % v)
    if isinstance(v, list):
        return '[' + ','.join(render_value(x) for x in v) + ']'
    return str(v)


def _human_to_desc(x: Any) -> str:
    return svm.human_to_desc(str(x))


def _fake_ref(t: Any) -> svm.MethodRef:
    return svm.MethodRef(
        str(t.desc_cls), str(t.name),
        [_human_to_desc(x) for x in t.params],
        _human_to_desc(str(t.ret)), -1, -1,
    )


def _parse_class_static_arrays(source_dx: Any, resolver: Any, cls: str) -> Dict[str, Any]:
    """Read arrays assigned by <clinit>, stopping before payload bytes."""
    out: Dict[str, Any] = {}
    try:
        for idx, val in source_dx.static_values(cls).items():
            out[source_dx.fields[idx].name] = val
    except Exception:
        pass
    try:
        em = next((e for e in source_dx.class_methods(cls)
                   if source_dx.methods[e.method_idx].name == '<clinit>'), None)
        if not em or not em.code_off:
            return out
        _regs_count, _ins_count, cu = source_dx.code_units(em.code_off)
    except Exception:
        return out
    regs: Dict[int, Any] = {}
    pc = 0
    while 0 <= pc < len(cu):
        w = cu[pc]
        op = w & 0xff
        aa = w >> 8
        try:
            if op in (0x0e, 0x0f, 0x10, 0x11):
                break
            if op == 0x12:
                n = (aa >> 4) & 0xf
                regs[aa & 0xf] = n - 16 if n >= 8 else n
                pc += 1; continue
            if op == 0x13:
                regs[aa] = svm.sign16(cu[pc + 1])
                pc += 2; continue
            if op == 0x14:
                regs[aa] = svm.sign32(cu[pc + 1] | (cu[pc + 2] << 16))
                pc += 3; continue
            if op == 0x15:
                regs[aa] = svm.sign32(cu[pc + 1] << 16)
                pc += 2; continue
            if op in (0x01, 0x04, 0x07):
                regs[aa & 0xf] = regs.get(aa >> 4)
                pc += 1; continue
            if op in (0x02, 0x05, 0x08):
                regs[aa] = regs.get(cu[pc + 1])
                pc += 2; continue
            if op in (0x03, 0x06, 0x09):
                regs[cu[pc + 1]] = regs.get(cu[pc + 2])
                pc += 3; continue
            if op == 0x23:  # new-array
                a, b = aa & 0xf, aa >> 4
                regs[a] = [0] * max(0, int(regs.get(b, 0) or 0))
                pc += 2; continue
            if op == 0x26:  # fill-array-data
                off = svm.sign32(cu[pc + 1] | (cu[pc + 2] << 16))
                vals = resolver._fill_payload(cu, pc + off)
                arr = regs.get(aa)
                if vals is not None and isinstance(arr, list):
                    arr[:len(vals)] = vals
                pc += 3; continue
            if 0x67 <= op <= 0x6d:  # sput
                f = source_dx.fields[cu[pc + 1]]
                out[f.name] = regs.get(aa)
                pc += 2; continue
        except Exception:
            break
        try:
            pc += resolver._ilen(op)
        except Exception:
            pc += 1
    return out


class V6EventVM(svm.DexVM):
    """Concrete event VM with side-effect tracing."""

    STATIC_KNOWN = {
        ('Ljava/lang/Integer;', 'valueOf'), ('Ljava/lang/Integer;', 'parseInt'),
        ('Ljava/lang/Long;', 'valueOf'), ('Ljava/lang/Long;', 'parseLong'),
        ('Ljava/lang/Short;', 'valueOf'), ('Ljava/lang/Byte;', 'valueOf'),
        ('Ljava/lang/Float;', 'valueOf'), ('Ljava/lang/Float;', 'parseFloat'),
        ('Ljava/lang/Double;', 'valueOf'), ('Ljava/lang/Double;', 'parseDouble'),
        ('Ljava/lang/Boolean;', 'valueOf'),
    }

    PAGE_COMMANDS = {
        'tw','t','ufnsui','uigo','us','ug','s','ss','sss','syso','java','javax',
        'cls','javanew','stop','end','activity','ngde','fr','loadjar','bfm','dh',
        'dhs','dhr','dha','hs','hw','ushsp','sqlite','hd','hws','ula','uls','uht','utw','uall',
        'uapp','time','zf','st','addv','json','huf','fw','sxb','fe','ft','fl','fi','fdir','sr','sl','sj','ssg','siof','slof','strim','slower','supper','uapplist','sit','uit','endutw','tws',
    }

    WIDGET_MUTATORS = {
        'width','height','text','src','background','backgroundColor','visibility',
        'enabled','alpha','currentItem','startAnimation','dismiss','show','close',
        'delete','write','renameTo','put','id','setText','setImageResource',
    }

    def __init__(self, dexes: List[svm.DexFile], source_dx: Any, resolver: Any,
                 max_steps: int = 250_000, max_depth: int = 180):
        super().__init__(dexes, max_steps=max_steps, max_depth=max_depth)
        self.source_dx = source_dx
        self.resolver = resolver
        self.calls: List[Dict[str, Any]] = []
        self.globals: Dict[str, Dict[str, Any]] = {}
        self.seeded: set[str] = set()
        self.exec_errors: List[str] = []
        self._call_stack: List[str] = []

    def seed_class(self, cls: str) -> None:
        if cls in self.seeded:
            return
        self.seeded.add(cls)
        try:
            values = _parse_class_static_arrays(self.source_dx, self.resolver, cls)
            for d in self.dexes:
                for name, value in values.items():
                    d.static_values[(cls, name)] = value
        except Exception as exc:
            self.exec_errors.append(f'seed {cls}: {exc}')

    def _unknown_result(self, ref: svm.MethodRef, args: List[Any]) -> Any:
        ret = ref.ret
        receiver = None
        actual = list(args)
        if args and (ref.cls, ref.name) not in self.STATIC_KNOWN:
            receiver, actual = args[0], list(args[1:])
        prefix = ''
        if receiver is not None and render_value(receiver) != 'null':
            prefix = render_value(receiver) + '.'
        text = prefix + ref.name + '(' + ','.join(render_value(x) for x in actual) + ')'
        if ret == 'V': return None
        if ret == 'Z': return False
        if ret in ('I','S','B','C','J'): return 0
        if ret in ('F','D'): return 0.0
        if ret == 'Ljava/lang/String;': return svm.Obj(ret, '')
        return svm.Obj(ret, Expr(text, ret))

    def _record_page(self, human: str, name: str, vals: List[Any], ret: str = 'V') -> Any:
        # Runnable helpers are represented as real V6 blocks rather than a Java
        # object construction expression.
        if name in ('t', 'ufnsui') and vals:
            target = vals[0]
            if isinstance(target, svm.Obj):
                before = len(self.calls)
                impl = self.dexes[0].find_method(svm.desc_to_human(target.typ), 'run', [])
                if impl:
                    child_calls: List[Dict[str, Any]] = []
                    parent_calls = self.calls
                    self.calls = child_calls
                    try:
                        self._exec(self.dexes[0], impl, [target], len(self._call_stack) + 1)
                    except Exception as exc:
                        self.exec_errors.append(f'{target.typ}.run: {exc}')
                    finally:
                        self.calls = parent_calls
                    self.calls.append({'kind': 'block', 'name': name, 'body': child_calls})
                    return None
        # Produce symbolic return values for expression helpers.  Pure
        # expression helpers are not emitted as standalone event statements;
        # they will appear inside the side-effect call that consumes them.
        pure_expr = {'dhs','dhr','dha','hs','huf','json','sj','sr','sl','ssg','siof','slof','strim','slower','supper','activity','st','zf','cls','javanew','loadjar','time','ug','fr','fe','fs','fi','fdir','uapplist'}
        if name not in pure_expr:
            self.calls.append({'kind': 'page', 'owner': human, 'name': name, 'args': vals, 'ret': ret})
        if name == 'dhs':
            text = 'dhs(' + ','.join(render_value(x) for x in vals) + ')'
            return svm.Obj('Landroid/view/animation/ScaleAnimation;', Expr(text, 'Landroid/view/animation/ScaleAnimation;'))
        if name == 'dhr':
            text = 'dhr(' + ','.join(render_value(x) for x in vals) + ')'
            return svm.Obj('Landroid/view/animation/RotateAnimation;', Expr(text, 'Landroid/view/animation/RotateAnimation;'))
        if name == 'dha':
            text = 'dha(' + ','.join(render_value(x) for x in vals) + ')'
            return svm.Obj('Landroid/view/animation/AlphaAnimation;', Expr(text, 'Landroid/view/animation/AlphaAnimation;'))
        if name == 'hs':
            text = 'hs(' + ','.join(render_value(x) for x in vals) + ')'
            return svm.Obj('Ljava/lang/String;', Expr(text, 'Ljava/lang/String;'))
        if name in ('huf','json','sj','sr','sl','ssg','siof','slof','strim','slower','supper','fr','fdir','uapplist'):
            text = name + '(' + ','.join(render_value(x) for x in vals) + ')'
            typ = 'Ljava/lang/String;' if name not in ('sl','uapplist') else 'Ljava/lang/Object;'
            return svm.Obj(typ, Expr(text, typ))
        if name in ('activity',):
            return svm.Obj('Landroid/app/Activity;', Expr('activity', 'Landroid/app/Activity;'))
        if name in ('java','javax','cls','loadjar','javanew','zf','st','time','ug','s','ss','sss'):
            text = name + '(' + ','.join(render_value(x) for x in vals) + ')'
            return svm.Obj('Ljava/lang/Object;', Expr(text))
        return None

    def _infer_static(self, dex: svm.DexFile, t: Any) -> bool:
        if bool(getattr(t, 'is_static', False)):
            return True
        if (str(t.desc_cls), str(t.name)) in self.STATIC_KNOWN:
            return True
        try:
            p = [_human_to_desc(x) for x in t.params]
            impl = dex.find_method(svm.desc_to_human(str(t.desc_cls)), str(t.name), p)
            if impl and (impl.access_flags & 0x0008):
                return True
        except Exception:
            pass
        if str(getattr(t, 'cls', '')) == 'java.lang.System' and str(t.name) in ('out','err'):
            return True
        return False

    def _normalize_actual(self, params: Iterable[Any], actual: List[Any]) -> List[Any]:
        out: List[Any] = []
        for p, x in zip(params, actual):
            ps = str(p)
            if ps in ('float','F'):
                out.append(java_float_bits(x))
            elif ps in ('double','D'):
                out.append(java_double_bits(x))
            elif ps in ('boolean','Z'):
                out.append(bool(x))
            else:
                out.append(x)
        out.extend(actual[len(out):])
        return out

    def _invoke_target(self, dex: svm.DexFile, t: Any, receiver: Any,
                       actual: List[Any], depth: int) -> Any:
        actual = self._normalize_actual(getattr(t, 'params', []), list(actual))
        is_static = self._infer_static(dex, t)
        if getattr(t, 'kind', '') == 'field':
            key = (str(t.desc_cls), str(t.name))
            if is_static or receiver is None:
                val = dex.static_values.get(key)
                if val is None:
                    self.seed_class(str(t.desc_cls))
                    val = dex.static_values.get(key)
                return val
            if isinstance(receiver, svm.Obj):
                val = receiver.fields.get(str(t.name))
                if val is not None:
                    return val
            # Page control fields (wb1, xxbj_7, tx_3, ...) are typed widget
            # wrappers.  Their field name is also the usable iApp control ID.
            ret_h = str(getattr(t, 'ret', ''))
            if ret_h.startswith('i6.runlibrary.app.v.'):
                ret = _human_to_desc(ret_h)
                cid = str(t.name)
                obj = svm.Obj(ret, Expr(cid, ret))
                obj.fields['control_id'] = cid
                obj.fields['widget_type'] = ret_h.split('.')[-1]
                return obj
            return None

        # The generated short[] slice decoder is stable across this protector:
        # String f(short[] table, int start, int length, int xorKey).
        if str(t.ret) in ('java.lang.String', 'Ljava/lang/String;') and len(actual) == 4 and isinstance(actual[0], list):
            try:
                arr, start, length, key = actual
                s = ''.join(chr((int(x) ^ int(key)) & 0xffff)
                            for x in arr[int(start):int(start) + int(length)])
                return svm.Obj('Ljava/lang/String;', s)
            except Exception:
                pass

        # st.<widget>(id) creates a typed wrapper around the runtime control ID.
        if str(t.desc_cls) == 'Li6/runlibrary/app/st;' and str(t.ret).startswith('i6.runlibrary.app.v.') and actual:
            ret = _human_to_desc(str(t.ret))
            cid = actual[0]
            obj = svm.Obj(ret, Expr(f'{t.name}({render_value(cid)})', ret))
            obj.fields['control_id'] = cid
            obj.fields['widget_type'] = str(t.ret).split('.')[-1]
            return obj

        ref = _fake_ref(t)
        # Generated page helper methods are instance methods in the protected
        # Java class, but their reflection wrapper often stores a null receiver.
        # Supply a synthetic page instance so the receiver is not mistaken for
        # the first V6 command argument (which previously produced sss(null),
        # stop(null,...) and similar invalid output).
        if (not is_static and receiver is None
                and str(t.desc_cls).startswith('Lcom/iApp/protection/LianYi/')):
            receiver = svm.Obj(str(t.desc_cls))
        args = ([] if is_static else [receiver]) + list(actual)
        # Call the regular interception layer, not resolver metadata again.
        return self._invoke_regular(dex, ref, args, depth)

    def _invoke_regular(self, dex: svm.DexFile, ref: svm.MethodRef,
                        args: List[Any], depth: int) -> Any:
        cls, name = ref.cls, ref.name
        human = svm.desc_to_human(cls)
        is_page = human.startswith('com.iApp.protection.LianYi.')

        # Preserve the Java string/object semantics used by the protector's
        # flattened switch dispatcher.  Falling through to a generic symbolic
        # value here makes hashCode/equals choose the wrong branch and can turn
        # a short event into an infinite loop.
        if cls == 'Ljava/lang/String;':
            value = self._obj_str(args[0]) if args else ''
            if name == 'intern':
                return args[0] if args else value
            if name == 'hashCode':
                h = 0
                for ch in value:
                    h = svm.sign32(31 * h + ord(ch))
                return h
            if name == 'equals':
                return value == self._obj_str(args[1] if len(args) > 1 else '')
            if name == 'isEmpty':
                return not value
            if name == 'startsWith':
                return value.startswith(self._obj_str(args[1] if len(args) > 1 else ''))
            if name == 'endsWith':
                return value.endswith(self._obj_str(args[1] if len(args) > 1 else ''))
            if name == 'contains':
                return self._obj_str(args[1] if len(args) > 1 else '') in value
            return super()._invoke(dex, ref, args, depth)
        if cls == 'Ljava/lang/Object;' and name == 'hashCode':
            value = self._obj_str(args[0]) if args else ''
            h = 0
            for ch in value:
                h = svm.sign32(31 * h + ord(ch))
            return h
        if cls in ('Ljava/lang/Float;', 'Ljava/lang/Double;'):
            if name == 'valueOf':
                return float(java_float_bits(args[0])) if cls == 'Ljava/lang/Float;' else float(java_double_bits(args[0]))
            if name in ('floatValue', 'doubleValue'):
                try:
                    return float(_unwrap(args[0] if args else 0))
                except Exception:
                    return 0.0
            if name in ('parseFloat', 'parseDouble'):
                try:
                    return float(self._obj_str(args[0]))
                except Exception:
                    return 0.0
        if cls in ('Ljava/lang/Integer;', 'Ljava/lang/Long;', 'Ljava/lang/Short;',
                   'Ljava/lang/Byte;', 'Ljava/lang/Boolean;'):
            if name in ('intValue', 'longValue', 'shortValue', 'byteValue'):
                try:
                    return int(_unwrap(args[0] if args else 0))
                except Exception:
                    return 0
            if name == 'booleanValue':
                return bool(_unwrap(args[0] if args else False))
        if cls == 'Ljava/lang/StringBuilder;':
            recv = args[0] if args else None
            actual = list(args[1:]) if len(args) > 1 else []
            if name == '<init>':
                if isinstance(recv, svm.Obj):
                    recv.fields['v6_parts'] = []
                    if actual:
                        recv.fields['v6_parts'].append(actual[0])
                return None
            if name == 'append':
                if isinstance(recv, svm.Obj):
                    recv.fields.setdefault('v6_parts', []).append(actual[0] if actual else '')
                    return recv
                return recv
            if name == 'toString':
                parts = recv.fields.get('v6_parts', []) if isinstance(recv, svm.Obj) else []
                rendered: List[str] = []
                for part in parts:
                    if isinstance(part, Expr):
                        rendered.append(part.text)
                    elif isinstance(part, svm.Obj) and isinstance(part.value, Expr):
                        rendered.append(part.value.text)
                    else:
                        rendered.append(render_value(_unwrap(part)))
                text = '+'.join(x for x in rendered if x not in ('', '""')) or '""'
                return svm.Obj('Ljava/lang/String;', Expr(text, 'Ljava/lang/String;'))
            return super()._invoke(dex, ref, args, depth)
        if cls in ('Ljava/lang/Character;', 'Landroid/util/Base64;', 'Ljava/util/Base64;'):
            return super()._invoke(dex, ref, args, depth)

        # Numeric box/unbox functions are frequent in wrapper targets.
        if (cls, name) in self.STATIC_KNOWN:
            a = args[0] if args else 0
            try:
                if cls == 'Ljava/lang/Float;': return float(java_float_bits(a))
                if cls == 'Ljava/lang/Double;': return float(java_double_bits(a))
                if cls == 'Ljava/lang/Boolean;': return bool(a)
                return int(self._obj_str(a) if isinstance(a, (str, svm.Obj)) else a)
            except Exception:
                return 0

        # JSON helpers are expression-capable in V6.  Keep the whole
        # request/parse chain symbolic so a network-dependent value can still
        # be embedded in a concrete UI command instead of disappearing.
        if is_page and name == 'json':
            vals = list(args[1:] if args and isinstance(args[0], svm.Obj) else args)
            text = 'json(' + ','.join(render_value(x) for x in vals) + ')'
            typ = ref.ret if ref.ret and ref.ret != 'V' else 'Ljava/lang/Object;'
            return svm.Obj(typ, Expr(text, typ))

        # Page global variables: ss/sss(key,value) and ss/sss(key).
        if is_page and name in ('ss','sss'):
            vals = list(args[1:] if args and isinstance(args[0], svm.Obj) else args)
            store = self.globals.setdefault(name, {})
            if len(vals) >= 2:
                store[self._obj_str(vals[0])] = vals[1]
                self.calls.append({'kind':'page','owner':human,'name':name,'args':vals})
                return None
            if len(vals) == 1:
                return store.get(self._obj_str(vals[0]), Expr(f'{name}({render_value(vals[0])})'))
            scope_obj = svm.Obj('Ljava/util/HashMap;', store)
            scope_obj.fields['iapp_scope'] = name
            return scope_obj

        # zf.dy is the generated equality helper used by V6 source such as
        # f(code == 200).  When the left side is a symbolic JSON value, follow
        # the success branch so its concrete ufnsui body can be recovered; the
        # emitted expressions still evaluate against the real response at run
        # time instead of baking in a fake literal value.
        if cls == 'Li6/runlibrary/app/zf;' and name == 'dy':
            left = args[1] if len(args) > 1 else None
            right = args[2] if len(args) > 2 else None
            lt = render_value(left)
            if 'json(' in lt and str(_unwrap(right)) == '200':
                return True
            return self._obj_str(left) == self._obj_str(right)

        # iApp global-map bridge: sss().get("key") is native sss("key").
        if cls in ('Ljava/util/Map;', 'Ljava/util/HashMap;', 'Ljava/util/LinkedHashMap;') and args:
            recv = args[0]
            scope = recv.fields.get('iapp_scope') if isinstance(recv, svm.Obj) else None
            if scope and name == 'get':
                key = args[1] if len(args) > 1 else ''
                return Expr(f'{scope}({render_value(key)})')
            if scope and name == 'put' and len(args) > 2:
                self.calls.append({'kind':'page','owner':human,'name':scope,'args':[args[1],args[2]],'ret':'V'})
                return None
            return super()._invoke(dex, ref, args, depth)

        # java.lang.Thread.start and page t()/ufnsui() both expand Runnable.run.
        if cls == 'Ljava/lang/Thread;' and name == '<init>' and args and isinstance(args[0], svm.Obj):
            args[0].fields['target'] = args[1] if len(args) > 1 else None
            return None

        # Same-dex inner-class constructors capture event values in fields.
        # Execute them with the original receiver object; dropping the receiver
        # creates a fresh synthetic instance and loses values such as a parsed
        # JSON message before ufnsui()/Thread.run() is expanded.
        if name == '<init>':
            impl = dex.impl_by_idx.get(ref.method_idx)
            if impl is not None and not cls.startswith(('Ljava/', 'Landroid/')):
                try:
                    self._exec(dex, impl, list(args), depth + 1)
                except Exception as exc:
                    self.exec_errors.append(f'{human}.<init>: {exc}')
                return None
            try:
                return super()._invoke(dex, ref, args, depth)
            except Exception:
                return None
        if cls == 'Ljava/lang/Thread;' and name == 'start' and args:
            thread = args[0]
            target = thread.fields.get('target') if isinstance(thread, svm.Obj) else None
            if isinstance(target, svm.Obj):
                impl = dex.find_method(svm.desc_to_human(target.typ), 'run', [])
                child: List[Dict[str, Any]] = []
                parent = self.calls
                self.calls = child
                try:
                    if impl: self._exec(dex, impl, [target], depth + 1)
                except Exception as exc:
                    self.exec_errors.append(f'{target.typ}.run: {exc}')
                finally:
                    self.calls = parent
                self.calls.append({'kind':'block','name':'t','body':child})
            return None

        # Page command methods are the actual iApp DSL operations.
        if is_page and name in self.PAGE_COMMANDS:
            vals = list(args[1:] if args and isinstance(args[0], svm.Obj) else args)
            return self._record_page(human, name, vals, ref.ret)

        # Widget wrappers.  Getter calls return a symbolic expression; mutators
        # become s(id,"method",...) statements.
        if cls.startswith('Li6/runlibrary/app/v/') and args:
            recv = args[0]
            actual = list(args[1:])
            cid = recv.fields.get('control_id') if isinstance(recv, svm.Obj) else None
            # V6 widget text getters are generic at the Java bridge level, but
            # their source-language value is a String.  Preserve that type so
            # values captured by t()/ufnsui() do not degrade to unknown type A.
            if not actual and name in ('text', 'getText'):
                control = render_value(cid) if cid is not None else render_value(recv)
                method = 'text' if name == 'text' else 'getText'
                expr = f'{control}.{method}()'
                return svm.Obj('Ljava/lang/String;', Expr(expr, 'Ljava/lang/String;'))
            if ref.ret != 'V' and not actual:
                return self._unknown_result(ref, args)
            self.calls.append({
                'kind':'widget', 'id':cid,
                'widget':svm.desc_to_human(cls).split('.')[-1],
                'name':name, 'args':actual,
            })
            return self._unknown_result(ref, args)

        # Execute same-dex helpers (including inner Runnable.run methods).
        impl = dex.impl_by_idx.get(ref.method_idx)
        if impl is None:
            try:
                impl = dex.find_method(human, name, ref.params)
            except Exception:
                impl = None
        if impl:
            # _exec accepts the receiver in the parameter register window.
            # Keep it for instance helpers so captured inner-class fields and
            # page state survive across method calls.
            call_args = list(args)
            try:
                return self._exec(dex, impl, call_args, depth + 1)
            except Exception as exc:
                self.exec_errors.append(f'{human}.{name}: {exc}')
                return self._unknown_result(ref, args)

        # Harmless Android/Java void calls are not emitted.  Known mutators from
        # external helpers are retained only as diagnostics.
        if ref.ret == 'V':
            return None
        return self._unknown_result(ref, args)

    def _invoke(self, dex: svm.DexFile, ref: svm.MethodRef,
                args: List[Any], depth: int) -> Any:
        # LianYi.NB reflection dispatcher.
        if ref.cls.startswith('LLianYi/NB/') and ref.name == 'n' and args:
            try:
                code = int(args[0])
                arity = len(ref.params)
                t = self.resolver.target(ref.cls, code, arity)
                if t is None and arity == 1:
                    c = self.resolver._constant_wrapper(ref.cls, code)
                    if c is not None:
                        return c.value
                if t is not None:
                    receiver = args[1] if len(args) >= 2 else None
                    actual: List[Any] = []
                    if len(args) >= 3:
                        av = args[2]
                        actual = av if isinstance(av, list) else ([] if av is None else [av])
                    return self._invoke_target(dex, t, receiver, actual, depth)
            except Exception as exc:
                self.exec_errors.append(f'NB {ref.cls} code={render_value(args[0])}: {exc}')
                return self._unknown_result(ref, args)

        # Fill static arrays before any page/helper method reads them.
        if ref.cls.startswith('Lcom/iApp/protection/LianYi/'):
            self.seed_class(ref.cls)
        return self._invoke_regular(dex, ref, args, depth)


def _default_arg(desc: str, index: int) -> Any:
    if desc in ('I','S','B','C','J'): return 0
    if desc == 'Z': return False
    if desc in ('F','D'): return 0.0
    if desc == 'Ljava/lang/String;': return svm.Obj(desc, '')
    names = {
        'Landroid/view/View;':'st_vW', 'Landroid/widget/AdapterView;':'st_pN',
        'Landroid/view/KeyEvent;':'st_eK', 'Landroid/content/Intent;':'st_iT',
    }
    return svm.Obj(desc, Expr(names.get(desc, f'st_p{index + 1}'), desc))


def _coerce_bridge_value(v: Any) -> Any:
    """Convert protector string literals in Object[] bridge args to V6 values."""
    if isinstance(v, svm.Obj) and v.typ == 'Ljava/lang/String;':
        raw = '' if v.value is None else str(v.value)
    elif isinstance(v, str):
        raw = v
    else:
        return v
    low = raw.strip().lower()
    if low == 'true': return True
    if low == 'false': return False
    if low == 'null': return None
    try:
        if raw.strip() and raw.strip().lstrip('-').isdigit():
            return int(raw.strip())
        if any(c in raw for c in '.eE'):
            return float(raw.strip())
    except Exception:
        pass
    return v


def _flatten_java_bridge_args(args: List[Any]) -> List[Any]:
    if args and isinstance(args[-1], list):
        tail = list(args[-1])
        # Object[] is encoded as type,value,type,value... . Keep type names as
        # strings and coerce only the value positions.
        flat: List[Any] = list(args[:-1])
        for i, item in enumerate(tail):
            flat.append(item if i % 2 == 0 else _coerce_bridge_value(item))
        return flat
    return args


def _strip_page_receiver_nulls(name: str, args: List[Any]) -> List[Any]:
    out = list(args)
    # Old wrappers sometimes leak the absent Java page receiver into arg0.
    while out and out[0] is None and name in {
        'tw','uigo','us','ug','syso','stop','end','bfm','ushsp','hd','hws',
        'ula','uls','uht','utw','uall','uapp','ngde','fr','sqlite'
    }:
        out.pop(0)
    return out


def _call_expression(call: Dict[str, Any]) -> str:
    if call.get('kind') != 'page':
        return ''
    name = str(call.get('name') or '')
    args = list(call.get('args') or [])
    if name in ('java','javax'):
        args = _flatten_java_bridge_args(args)
    args = _strip_page_receiver_nulls(name, args)
    return name + '(' + ','.join(render_value(x) for x in args) + ')'


def _prune_calls(calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop pure bridge intermediates and empty/invalid recovered blocks."""
    # First recursively prune blocks.
    work: List[Dict[str, Any]] = []
    for call in calls:
        if call.get('kind') == 'block':
            body = _prune_calls(list(call.get('body') or []))
            if body:
                c = dict(call); c['body'] = body; work.append(c)
        else:
            work.append(call)
    exprs = [_call_expression(c) for c in work]
    out: List[Dict[str, Any]] = []
    for i, call in enumerate(work):
        if call.get('kind') == 'page':
            name = str(call.get('name') or '')
            expr = exprs[i]
            # Getter/intermediate bridge calls that are embedded in a later
            # statement are not standalone V6 operations.
            if name in {'activity','dhs','st','zf','cls','javanew','loadjar','time','ug'}:
                continue
            if name in {'java','javax'} and expr and any(expr in later for later in exprs[i+1:] if later):
                continue
            args = _strip_page_receiver_nulls(name, list(call.get('args') or []))
            # Do not emit malformed commands with an unknown required object.
            if name == 'dh' and (not args or args[0] is None):
                continue
            if name == 'ufnsui' and not [x for x in args if x is not None]:
                continue
        out.append(call)
    return out


def _render_call(call: Dict[str, Any], indent: str = '') -> List[str]:
    kind = call.get('kind')
    if kind == 'block':
        name = str(call.get('name') or 't')
        out = [indent + name + '()', indent + '{']
        for child in call.get('body') or []:
            out.extend(_render_call(child, indent + '  '))
        out.append(indent + '}')
        return out
    if kind == 'page':
        name = str(call.get('name') or '')
        args = list(call.get('args') or [])
        if not name or name in ('st','zf'):
            return []
        args = _strip_page_receiver_nulls(name, args)
        if name in ('java','javax'):
            args = _flatten_java_bridge_args(args)
        if name == 'dh' and (not args or args[0] is None):
            return []
        return [indent + name + '(' + ','.join(render_value(x) for x in args) + ')']
    if kind == 'widget':
        cid = call.get('id')
        name = str(call.get('name') or '')
        args = call.get('args') or []
        if cid is None or render_value(cid) in ('null',''):
            return []
        all_args = [render_value(cid), json.dumps(name, ensure_ascii=False)] + [render_value(x) for x in args]
        return [indent + 's(' + ','.join(all_args) + ')']
    return []


def _dedupe_lines(lines: List[str]) -> List[str]:
    out: List[str] = []
    for line in lines:
        # Do not dedupe structural braces or repeated operations inside blocks.
        if line.strip() in ('{','}') or not out or line != out[-1]:
            out.append(line)
    return out



_DEXFILE_CACHE: Dict[int, svm.DexFile] = {}


def _get_dexfile(source_dx: Any, dex_bytes: bytes) -> svm.DexFile:
    key = id(source_dx)
    cached = _DEXFILE_CACHE.get(key)
    if cached is None:
        cached = svm.DexFile(dex_bytes)
        _DEXFILE_CACHE[key] = cached
    return cached

def recover_event_method(source_dx: Any, dex_bytes: bytes, resolver: Any,
                         encoded: Any, owner_cls: str) -> Tuple[List[str], Dict[str, Any]]:
    """Execute one encoded event method and return safe V6 source lines."""
    report: Dict[str, Any] = {'ok': False, 'calls': 0, 'errors': []}
    try:
        df = _get_dexfile(source_dx, dex_bytes)
        impl = df.impl_by_idx.get(encoded.method_idx)
        if impl is None:
            report['errors'].append('method_impl_not_found')
            return [], report
        mr = source_dx.methods[encoded.method_idx]
        args = [_default_arg(p, i) for i, p in enumerate(mr.proto.params)]
        vm = V6EventVM([df], source_dx, resolver)
        vm.seed_class(owner_cls)
        try:
            vm._exec(df, impl, args, 0)
        except Exception as exc:
            vm.exec_errors.append(f'root: {exc}')
        vm.calls = _prune_calls(vm.calls)
        lines: List[str] = []
        for call in vm.calls:
            lines.extend(_render_call(call))
        lines = _dedupe_lines([x for x in lines if x.strip()])
        report.update({
            'ok': bool(lines), 'calls': len(vm.calls),
            'errors': vm.exec_errors[-30:],
            'line_count': len(lines),
        })
        return lines, report
    except Exception as exc:
        report['errors'].append(f'{type(exc).__name__}: {exc}')
        return [], report
