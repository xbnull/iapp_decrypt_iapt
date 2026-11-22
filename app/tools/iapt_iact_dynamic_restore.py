#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strict reverse iACT alias restore with composed-token recovery.

The mapping table is standard_call=encrypted_alias. Restore/decrypt must replace
RIGHT -> LEFT only. V8 matched only complete aliases; V9 also handles aliases
that were produced by encrypting only the suffix of a built-in call, for example
ucnmsb( = u + cnmsb( -> us(.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

MAPPING_VERSION = 9
SOURCE_SUFFIXES = {".iyu", ".myu", ".ijava", ".java", ".mlua", ".ilua", ".mjs", ".ijs", ".txt"}

_RAW_TABLE = r"""
f(=LianYi666(|for(=LianYi315829(|w(=wcnm(|t(=nmlgb(|ssj(=wcnmb(|syso(=nmsl(|tw(=LianYi(|fd(=csnmb(|fe(=LianYiNB(|fs(=LYnb(|fr(=ly666(|fc(=315829(|fw(=feiwu(|fl(=152231(|ft(=cnmlgb(|fdir(=wcnm666(|fuz(=lynb666(|fuzs(=nssjb(|fo(=Lianyinb666(|fj(=qwed(|s(=cnmsb(|s2(=cnmgcb(|sn(=jsnmgb(|s+(=njnmbn(|s-(=jnmb(|s*(=cnmbn(|s/(=ncnmba(|s%(=sgyg(|ss(=nzznmb(|sr(=nthnmb(|sj(=njqnmlgb(|sl(=nsznmb(|siof(=zxhNB(|slof(=Zxhnb666(|ssg(=hqnmb(|slg(=6666666(|strim(=nhly(|slower(=bzdsmhs(|supper(=xjbjm(|stop(=LianYi668(|sran(=LianYisjs(|nsz(=bzdsmgdx(|sgsz(=fwzdsz(|sssz(=szsz(|sgszl(=LianYicnm(|hs(=lynb886(|hd(=lycnmb(|hw(=cnmxbzz(|hws(=nknmbn(|ug(=涟漪牛逼(|us(=你看你妈逼呢(|uigo(=傻狗(|utw(=艹你妈逼(|endutw(=傻子(|end(=你逆你妈逼啊(|ends(=死逼(|bfm(=没见过涟漪加密?(|bfms(=涟漪男神(|ula(=傻了吧唧的(|uls(=涟漪草泥马(|ulas(=废物(|ulag(=那咋了(|usms(=煞笔吧你(|ucall(=涟漪爱艹你妈(|time(=草泥马那咋了(|fi(=看你妈逼去吧(|stobm(=看你爸的屌啊(|sutf8to(=你跳楼吧(|uycl(=涟漪20cm(|ushsp(=涟漪天天艹逼(|bfv(=涟漪888(|bfvs(=斯密马赛(|bfvss(=控制你妈逼(|ftz(=涟漪工具箱(|uapp(=即将打开你妈逼(|uapplist(=我儿子的列表(|uapplistgo(=后台蛀虫(|uninapp(=删了吧没意思(|huf(=你妈飞走咯(|nvw(=听说涟漪是v3神(|uall(=看看你妈逼(|urvw(=LianYi男神(|sbp(=割你妈逼(|sdeg(=调试你妈逼(|bfs(=保存你妈逼图(|tot(=获取了你妈逼(|tzz(=旋转你麻痹图(|tsf(=可放大你妈逼图(|tfz(=反转你妈逼图(|sxb(=逼毛好多(|shb(=看看你妈的逼(|tcc(=你妈逼尺寸(|usjxm(=你妈逼要休息了(|addv(=你奶奶被我骑走咯(|gvs(=你喝你妈淫水(|aslist(=天天你妈逼(|sslist(=好累啊(|gslist(=添加数据列表(|gslistl(=你妈逼有多少根毛(|dslist(=扯掉你妈逼毛(|gslistsz(=好累啊不想写了(|gslistis(=焯真不想写了(|gslistiof(=包含着你妈逼(|gslistlof(=涟漪大王想睡觉了(|nuibs(=选择你妈逼颜色(|ngde(=涟漪大王(|sit(=黑客代码(|uit(=涟漪扣你妈逼(|git(=想哭了(|uqr(=看看你妈逼长啥样(|zdp(=不知道这什么鬼东西(|zpd(=死函数(|zps(=骚逼(|zsp(=我想跳楼了(|lan(=你爸被我骑着飞走咯(|sjxx(=主人的手机信息(|simsi(=GG鸡肉肠(|simei(=手机设备码(|endkeyboard(=关闭隐藏键盘(|hdfl(=下载器(|hdfla(=好累啊死函数(|hdd(=配置下载(|hdda(=增加下载(|hddg(=下载属性(|hdds(=属性2(|hdduigo(=跳转下载(|swh(=分辨率(|ufnsui(=傻逼东西(|se(=黑客正则代码(|usg(=闪瞎你妈逼(|uzd(=自慰棒(|usxq(=看看肥猪(|usxh(=看风景(|usx(=摄像头(|ujp(=截屏(|bly(=间谍代码(|sqlite(=黑客数据库(|sql(=数据库操作(|sqlsele(=查询数据库(|dha(=操你妈咋滴(|dhs(=渐变动画(|dht(=移动你妈逼(|dhr(=旋转你妈逼控件(|dhset(=汪汪队集合(|dhas(=动画执行(|dhast(=神秘黑客函数(|dh(=可以控制你妈的逼(|dhon(=监听黑客代码(|dhb(=动画背景(|hsas(=浏览器交换(|has(=神秘交互代码(|uxf(=你妈的逼飞起来(|tts(=机器人讲话(|blp(=录逼(|otob(=黑客常用(|btoo(=解密还原(|sot(=网络通信(|sota(=单个通讯(|loadso(=加载你妈逼代码(|loadjar(=加载库(|cls(=完整接口(|javacb(=自定义回调(|javanew(=初始你妈逼(|java(=原神(|javax(=调用原神(|javags(=访问原神(|javass(=设置原神(|res(=原神路径(|clssm(=获取原神接口(|zj(=原神666(|call(=交互原神(|json(=原神数据分析(|utb(=脑袋晕晕的(|tws(=涟漪无敌你随意(|uht(=滑动原神控制(|cast(=强制转换原神(|yul(=加载原神布局(|rps(=请求原神权限(
""".strip()


def _parse_table(raw: str = _RAW_TABLE) -> Tuple[List[Tuple[str, str]], Dict[str, List[str]]]:
    pairs: List[Tuple[str, str]] = []
    by_alias: Dict[str, List[str]] = {}
    compact = raw.replace("\r", "").replace("\n", "")
    for item in compact.split("|"):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError("invalid iACT mapping item: " + item)
        standard, alias = item.split("=", 1)
        standard, alias = standard.strip(), alias.strip()
        if not standard or not alias:
            raise ValueError("empty iACT mapping side: " + item)
        if not standard.endswith("(") or not alias.endswith("("):
            raise ValueError("iACT mapping calls must end with '(' : " + item)
        pairs.append((standard, alias))
        by_alias.setdefault(alias, []).append(standard)
    return pairs, {k: v for k, v in by_alias.items() if len(v) > 1}


TABLE, AMBIGUOUS_ALIASES = _parse_table()

# RIGHT -> LEFT only. First declaration wins when aliases collide.
DECRYPT_MAP: Dict[str, str] = {}
for _standard, _alias in TABLE:
    DECRYPT_MAP.setdefault(_alias, _standard)

ALIASES_LONG_FIRST = sorted(DECRYPT_MAP, key=lambda s: (-len(s), s))
ALIASES_BY_FIRST: Dict[str, List[str]] = {}
for _alias in ALIASES_LONG_FIRST:
    ALIASES_BY_FIRST.setdefault(_alias[0], []).append(_alias)

STANDARD_CALLS = {standard for standard, _alias in TABLE}
ALIAS_CALLS = set(DECRYPT_MAP)
STANDARD_NAMES = {standard[:-1] for standard, _alias in TABLE}
DECRYPT_NAME_MAP: Dict[str, str] = {}
for _alias, _standard in DECRYPT_MAP.items():
    DECRYPT_NAME_MAP[_alias[:-1]] = _standard[:-1]

# Some iACT samples obfuscate only the tail of a compound call name.  Example:
# standard us( is u + s(.  If s( is mapped to cnmsb(, the sample can contain
# ucnmsb(.  V8 correctly refused to replace cnmsb( inside an identifier, but
# that left ucnmsb( unrecovered.  Derive every safe prefix+alias -> full
# standard call where the resulting full standard name is present in the table.
COMPOSED_SUFFIX_ARTIFACTS: Dict[str, str] = {}
for _alias_name, _std_tail in DECRYPT_NAME_MAP.items():
    if not _alias_name.isascii() or not _alias_name.replace('_', '').isalnum():
        continue
    if not _std_tail:
        continue
    for _full_std in sorted(STANDARD_NAMES, key=lambda s: (-len(s), s)):
        if _full_std == _std_tail or not _full_std.endswith(_std_tail):
            continue
        _prefix = _full_std[: len(_full_std) - len(_std_tail)]
        if not _prefix or not all((c == '_' or (c.isascii() and c.isalnum())) for c in _prefix):
            continue
        _artifact = _prefix + _alias_name + "("
        _target = _full_std + "("
        if _artifact not in STANDARD_CALLS and _artifact not in ALIAS_CALLS:
            COMPOSED_SUFFIX_ARTIFACTS.setdefault(_artifact, _target)

# Clean up artifacts produced by the broken forward substring replacer.
BROKEN_FORWARD_ARTIFACTS: Dict[str, str] = {}
for standard, _alias in TABLE:
    std_name = standard[:-1]
    if not std_name:
        continue
    for short_standard, short_alias in TABLE:
        short_name = short_standard[:-1]
        if not short_name or short_standard == standard:
            continue
        if std_name.endswith(short_name):
            artifact = std_name[: len(std_name) - len(short_name)] + short_alias
            if artifact not in STANDARD_CALLS and artifact not in ALIAS_CALLS:
                BROKEN_FORWARD_ARTIFACTS.setdefault(artifact, standard)
BROKEN_FORWARD_ARTIFACTS.setdefault("twcnm(", "tw(")

BROKEN_LONG_FIRST = sorted(BROKEN_FORWARD_ARTIFACTS, key=lambda s: (-len(s), s))
BROKEN_BY_FIRST: Dict[str, List[str]] = {}
for _token in BROKEN_LONG_FIRST:
    BROKEN_BY_FIRST.setdefault(_token[0], []).append(_token)

COMPOSED_LONG_FIRST = sorted(COMPOSED_SUFFIX_ARTIFACTS, key=lambda s: (-len(s), s))
COMPOSED_BY_FIRST: Dict[str, List[str]] = {}
for _token in COMPOSED_LONG_FIRST:
    COMPOSED_BY_FIRST.setdefault(_token[0], []).append(_token)


def _is_ascii_ident(ch: str) -> bool:
    return bool(ch) and (ch == "_" or (ch.isascii() and ch.isalnum()))


def _left_boundary(text: str, pos: int) -> bool:
    if pos <= 0:
        return True
    return not _is_ascii_ident(text[pos - 1])


def _match_source_token(text: str, pos: int) -> Tuple[str, str, str] | None:
    if not _left_boundary(text, pos):
        return None
    ch = text[pos]

    # First repair complete broken/composed call tokens.  These are checked at
    # the token start, so ucnmsb( becomes us( without ever matching cnmsb( as a
    # substring in the middle of an identifier.
    for token in BROKEN_BY_FIRST.get(ch, ()):  # longest first
        if text.startswith(token, pos):
            return token, BROKEN_FORWARD_ARTIFACTS[token], "fixed_forward_artifact"
    for token in COMPOSED_BY_FIRST.get(ch, ()):  # longest first
        if text.startswith(token, pos):
            return token, COMPOSED_SUFFIX_ARTIFACTS[token], "fixed_composed_suffix_alias"

    # Then handle normal exact aliases: wcnm( -> w(, LianYi( -> tw(, ...
    for alias in ALIASES_BY_FIRST.get(ch, ()):  # longest first
        if text.startswith(alias, pos):
            return alias, DECRYPT_MAP[alias], "reverse_alias"
    return None


def restore_text(text: str) -> Tuple[str, Dict[str, int], Dict[str, int]]:
    """Reverse encrypted aliases while preserving quoted strings/comments."""
    out: List[str] = []
    counts: Dict[str, int] = {}
    kinds: Dict[str, int] = {}
    i, n = 0, len(text)
    state = "code"
    quote = ""
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == "string":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                state = "code"
                quote = ""
            i += 1
            continue
        if state == "line_comment":
            out.append(ch)
            i += 1
            if ch in "\r\n":
                state = "code"
            continue
        if state == "block_comment":
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append(nxt)
                i += 2
                state = "code"
            else:
                i += 1
            continue

        if ch in ('"', "'"):
            state, quote = "string", ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            state = "line_comment"
            out.extend((ch, nxt))
            i += 2
            continue
        if ch == "/" and nxt == "*":
            state = "block_comment"
            out.extend((ch, nxt))
            i += 2
            continue

        hit = _match_source_token(text, i)
        if hit:
            source_token, repl, kind = hit
            out.append(repl)
            counts[repl] = counts.get(repl, 0) + 1
            kinds[kind] = kinds.get(kind, 0) + 1
            i += len(source_token)
            continue

        out.append(ch)
        i += 1
    return "".join(out), counts, kinds


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_source_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES and path.name != "iact_dynamic_restore_report.json":
            yield path


def _residual_alias_count(text: str) -> int:
    total = 0
    for alias in ALIASES_LONG_FIRST:
        total += text.count(alias)
    for token in BROKEN_LONG_FIRST:
        total += text.count(token)
    for token in COMPOSED_LONG_FIRST:
        total += text.count(token)
    return total


def restore_tree(root: Path, write_report: bool = True) -> Dict[str, object]:
    root = Path(root)
    if not root.exists() or not root.is_dir():
        raise ValueError("source root does not exist: " + str(root))

    changed_files = 0
    scanned_files = 0
    replacements = 0
    residual_aliases = 0
    per_file: List[Dict[str, object]] = []
    aggregate: Dict[str, int] = {}
    aggregate_kinds: Dict[str, int] = {}

    for path in _iter_source_files(root):
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            continue
        scanned_files += 1
        restored, counts, kinds = restore_text(text)
        residual = _residual_alias_count(restored)
        residual_aliases += residual
        if not counts:
            if residual:
                per_file.append({
                    "path": str(path.relative_to(root)).replace("\\", "/"),
                    "replacements": 0,
                    "residual_alias_like_tokens": residual,
                })
            continue
        new_raw = restored.encode("utf-8")
        path.write_bytes(new_raw)
        count = sum(counts.values())
        changed_files += 1
        replacements += count
        for key, value in counts.items():
            aggregate[key] = aggregate.get(key, 0) + value
        for key, value in kinds.items():
            aggregate_kinds[key] = aggregate_kinds.get(key, 0) + value
        per_file.append({
            "path": str(path.relative_to(root)).replace("\\", "/"),
            "replacements": count,
            "kinds": dict(sorted(kinds.items())),
            "calls": dict(sorted(counts.items())),
            "residual_alias_like_tokens": residual,
            "before_sha256": _sha256_bytes(raw),
            "after_sha256": _sha256_bytes(new_raw),
        })

    report: Dict[str, object] = {
        "ok": True,
        "mode": "iact_dynamic_decrypt_reverse_only",
        "mapping_version": MAPPING_VERSION,
        "mapping_direction": "encrypted_alias_to_standard_call",
        "composed_suffix_artifacts": len(COMPOSED_SUFFIX_ARTIFACTS),
        "mapping_pairs": len(TABLE),
        "unique_encrypted_aliases": len(DECRYPT_MAP),
        "ambiguous_aliases": AMBIGUOUS_ALIASES,
        "ambiguity_policy": "first declaration wins",
        "scanned_files": scanned_files,
        "changed_files": changed_files,
        "replacement_count": replacements,
        "replacement_kinds": dict(sorted(aggregate_kinds.items())),
        "residual_alias_like_tokens": residual_aliases,
        "calls": dict(sorted(aggregate.items())),
        "files": per_file,
    }
    if write_report:
        (root / "iact_dynamic_restore_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reverse iACT encrypted aliases in an extracted source tree")
    parser.add_argument("root", type=Path)
    args = parser.parse_args(argv)
    report = restore_tree(args.root)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
