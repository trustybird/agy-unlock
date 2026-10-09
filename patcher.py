#!/usr/bin/env python3
"""
agy-unlock-analog v2 — открытый аналог Antigravity Unlock.

Покрывает три цели:
- manager (Antigravity 2.0, language_server): ДВА x64-гейта + ARM64
- cli (agy): x64 (v1/v2) + ARM64
- ide (Antigravity IDE, main.js): isGoogleInternal -> true

Почему старый Open_AG_Patcher V1.3.8 (2026-09-21) «не работает теперь»:
- он патчит только hasValidAuth-гейт менеджера (cmp byte[rax+8],0),
  а рядом в том же auth-флоу есть второй eligibility-гейт
  (test rax,rax + jne, смещение ~0x1F0), который V1.3.8 не трогает;
- CLI-гейт в новых сборках сменил хвост (spills +0xd8/+0xe0/+0xe8),
  короткий паттерн V1.3.8 либо не уникален, либо не совпадает;
- IDE main.js минифицируется заново каждой версией — жёсткий паттерн
  V1.3.8 не находит переименованное поле;
- часть проверок переехала на сервер — без DNS с подменой гео
  клиентского патча недостаточно (как честно пишет и xbox_dns/175).

Сигнатуры гейтов (байтовые паттерны, не смещения — переживают обновления
до пересборки функции):
- MGR_X64_AUTH (hasValidAuth, OAP/QNIX/vezlin, MIT):
    orig    80 78 08 00 74 . 48 8B . 24 . 48 89 . 60
    patched C6 40 08 01 90 90 + тот же хвост
    fix     C6 40 08 01 90 90 @+0  (mov byte[rax+8],1; nop nop)
- MGR_X64_ELIG (eligibility screen, xbox_dns/175, реверс 2.21.1):
    7F 0D 0F 1F 40 00 48 85 C0 0F 85 ?? ?? ?? ?? 4C 8B 94 24 98 ..
    4D 85 D2 74 06 4D 8B 52 08 EB 04 45 31 D2 90 4D 85 D2 75 ??
    fix1 @+9:  0F 85 .. .. .. .. -> 90 90 90 90 90 90 (jne -> nop*6)
    fix2 @+41: 75 -> EB (jne short -> jmp short, операнд цел)
- CLI_X64_V2 (QNIX, CLI 1.2.16+, MIT): test + je + cmp + jne + call + spills
    fix 48 85 C0 90 @+9
- CLI_X64_V1 (OAP V1.3.8, GPL-3.0): тот же префикс без spill-хвоста (старые CLI)
- ARM64 гейты: портированы из OAP V1.3.8 (GPL-3.0) / QNIX (MIT), локально
  проверить не на чем (нет ARM-бинарей) — помечены experimental.
- IDE JS (vezlin tolerant + QNIX single-replace):
    resetIsTierGCPTos()[ws][,;][ws](this|X.y...).isGoogleInternal -> true

Атрибуция: байт-сигнатуры MGR/CLI/ARM/IDE — AvenCores Open AG Patcher
(GPL-3.0) / QNIX-Dev eligibility-antigravity-patcher (MIT) / vezlin1
antigravity-bypass-russia (MIT). Каркас сканера секций/бэкапов — по мотивам
QNIX manager.py (MIT). Весь код здесь — заново, только stdlib, без телеметрии.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import re
import shutil
import struct
import sys
import time
from pathlib import Path

VERSION = "2.1.0-analog"
TOOL_NAME = "agy-unlock-analog"
SIGPACK_FORMAT = 1

# ---------------------------------------------------------------- gates ---

class SigError(LookupError):
    pass


class SigAmbiguous(LookupError):
    pass


def _unique_search(pattern: re.Pattern, data: bytes, ranges, label: str):
    found = None
    for start, end in ranges:
        pos = start
        while pos < end:
            m = pattern.search(data, pos, end)
            if not m:
                break
            if found is not None:
                raise SigAmbiguous(f"{label}: сигнатура не уникальна — отказываюсь гадать")
            found = m
            pos = max(m.end(), m.start() + 1)
    return found


class Gate:
    """Один бинарный гейт: orig/patched regex, список (delta, bytes) фиксов."""

    def __init__(self, sig, patched, fixes, desc="", arch=None):
        self.sig = re.compile(sig, re.S)
        self.patched = re.compile(patched, re.S)
        self.fixes = list(fixes)  # [(delta:int, bytes)]
        self.desc = desc
        self.arch = arch  # None = любая

    def state(self, data: bytes, ranges) -> tuple[str, int]:
        o = _unique_search(self.sig, data, ranges, self.desc or "gate")
        p = _unique_search(self.patched, data, ranges, (self.desc or "gate") + " [patched]")
        if o and p:
            raise SigAmbiguous(f"{self.desc}: есть и orig, и patched — каша, нужен чистый бэкап")
        if p:
            return ("patched", p.start())
        if o:
            return ("unpatched", o.start())
        raise SigError(f"{self.desc}: сигнатура не найдена (неподдерживаемая версия?)")


# -- manager x64 hasValidAuth (OAP V1.3.8 / QNIX / vezlin) --
MGR_X64_AUTH = Gate(
    rb"\x80\x78\x08\x00\x74.\x48\x8b.\x24.\x48\x89.\x60",
    rb"\xc6\x40\x08\x01\x90\x90\x48\x8b.\x24.\x48\x89.\x60",
    [(0, b"\xc6\x40\x08\x01\x90\x90")],
    desc="hasValidAuth=true (manager x64)",
    arch="x64",
)

# -- manager x64 eligibility (xbox_dns/175, language_server 2.21.1) --
# None = wildcard байт. Фиксов два, применяются атомарно.
ELIG_ORIG = [
    0x7F, 0x0D, 0x0F, 0x1F, 0x40, 0x00, 0x48, 0x85, 0xC0,
    0x0F, 0x85, None, None, None, None,
    0x4C, 0x8B, 0x94, 0x24, 0x98, 0x00, 0x00, 0x00,
    0x4D, 0x85, 0xD2, 0x74, 0x06, 0x4D, 0x8B, 0x52, 0x08,
    0xEB, 0x04, 0x45, 0x31, 0xD2, 0x90, 0x4D, 0x85, 0xD2,
    0x75, None,
]
ELIG_OFF1, ELIG_LEN1 = 9, 6
ELIG_OFF2 = 41
ELIG_FIX1 = bytes([0x90] * 6)
ELIG_FIX2 = 0xEB
ELIG_ORIG_OP2 = 0x75


def _elig_find(data: bytes, ranges):
    """Ищет префикс 7F 0D 0F 1F 40 00 48 85 C0 только в кодовых секциях,
    возвращает (kind, offset). kind: patched|unpatched. Бросает SigError."""
    needle = bytes([0x7F, 0x0D, 0x0F, 0x1F, 0x40, 0x00, 0x48, 0x85, 0xC0])
    cands = []
    for rs, re_ in ranges:
        pos = data.find(needle, rs, re_)
        while pos != -1:
            cands.append(pos)
            if len(cands) > 16:
                break
            pos = data.find(needle, pos + 1, re_)
    if not cands:
        raise SigError("eligibility screen: сигнатура не найдена (неподдерживаемая версия?)")
    if len(cands) > 1:
        # несколько префиксов — сверяем полную маску, должен остаться один
        full = []
        for c in cands:
            if c + len(ELIG_ORIG) > len(data):
                continue
            ok = True
            for j, pb in enumerate(ELIG_ORIG):
                if j in (ELIG_OFF1, ELIG_OFF1 + 1, ELIG_OFF1 + 2, ELIG_OFF1 + 3,
                         ELIG_OFF1 + 4, ELIG_OFF1 + 5, ELIG_OFF2, ELIG_OFF2 + 1):
                    continue
                if pb is None:
                    continue
                if data[c + j] != pb:
                    ok = False
                    break
            if ok:
                full.append(c)
        if len(full) != 1:
            raise SigAmbiguous(
                f"eligibility screen: кандидатов {len(full)} — отказываюсь гадать")
        cands = full
    c = cands[0]
    if c + len(ELIG_ORIG) > len(data):
        raise SigError("eligibility screen: обрезок в конце файла")
    for j, pb in enumerate(ELIG_ORIG):
        if j in (ELIG_OFF1, ELIG_OFF1 + 1, ELIG_OFF1 + 2, ELIG_OFF1 + 3,
                 ELIG_OFF1 + 4, ELIG_OFF1 + 5, ELIG_OFF2, ELIG_OFF2 + 1):
            continue
        if pb is None:
            continue
        if data[c + j] != pb:
            raise SigError("eligibility screen: сигнатура не найдена (неподдерживаемая версия?)")
    b1 = data[c + ELIG_OFF1: c + ELIG_OFF1 + ELIG_LEN1]
    b2 = data[c + ELIG_OFF2]
    if b1 == ELIG_FIX1 and b2 == ELIG_FIX2:
        return ("patched", c)
    if b1[0] == 0x0F and b1[1] == 0x85 and b2 == ELIG_ORIG_OP2:
        return ("unpatched", c)
    raise SigError("eligibility screen: неизвестное состояние джампов")


class EligGate:
    desc = "eligibility screen off (manager x64, xbox)"

    def state(self, data, ranges):
        return _elig_find(data, ranges)

    def apply(self, buf: bytearray, off: int):
        buf[off + ELIG_OFF1: off + ELIG_OFF1 + ELIG_LEN1] = ELIG_FIX1
        buf[off + ELIG_OFF2] = ELIG_FIX2


ELIG_GATE = EligGate()

# -- cli x64 v2 (QNIX, CLI 1.2.16+: со spill-хвостом) --
CLI_X64_V2 = Gate(
    rb"\x48\x85\xc0\x0f\x84....\x80\x78\x08\x00\x0f\x85...."
    rb"\xe8....\x48\x89\x84\x24\xd8\x00\x00\x00"
    rb"\x48\x89\x9c\x24\xe0\x00\x00\x00\x48\x89\x8c\x24\xe8\x00\x00\x00",
    rb"\x48\x85\xc0\x0f\x84....\x48\x85\xc0\x90\x0f\x85...."
    rb"\xe8....\x48\x89\x84\x24\xd8\x00\x00\x00"
    rb"\x48\x89\x9c\x24\xe0\x00\x00\x00\x48\x89\x8c\x24\xe8\x00\x00\x00",
    [(9, b"\x48\x85\xc0\x90")],
    desc="eligibility screen off (cli x64 v2)",
    arch="x64",
)

# -- cli x64 v1 (OAP V1.3.8, старые CLI без spill-хвоста) --
CLI_X64_V1 = Gate(
    rb"\x48\x85\xc0\x0f\x84....\x80\x78\x08\x00\x0f\x85....",
    rb"\x48\x85\xc0\x0f\x84....\x48\x85\xc0\x90\x0f\x85....",
    [(9, b"\x48\x85\xc0\x90")],
    desc="eligibility screen off (cli x64 v1)",
    arch="x64",
)

# -- manager arm64 (OAP/QNIX/vezlin; experimental — ARM-бинарей под рукой нет) --
MGR_ARM64 = Gate(
    rb"\x03\x20\x40\x39[\x03\x23\x43\x63\x83\xa3\xc3\xe3].."
    rb"\x36(?:....){1,2}\x03\x10\x06\xa9",
    rb"\x23\x00\x80\x52\x03\x20\x00\x39(?:....){1,2}\x03\x10\x06\xa9",
    [(0, b"\x23\x00\x80\x52\x03\x20\x00\x39")],
    desc="hasValidAuth=true (manager arm64, experimental)",
    arch="arm64",
)

# -- cli arm64 (OAP V1.3.8 + QNIX 1.2.16 контекст; experimental) --
CLI_ARM64 = Gate(
    rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4"
    rb"\x02\x20\x40\x39[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37"
    rb"...[\x94-\x97]",
    rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4"
    rb"\x22\x00\x80\x52[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37"
    rb"...[\x94-\x97]",
    [(8, b"\x22\x00\x80\x52")],
    desc="eligibility screen off (cli arm64, experimental)",
    arch="arm64",
)

# -- ide main.js (vezlin tolerant regex + QNIX single-replace) --
IDE_STOCK_RE = re.compile(
    r"(resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*)(?:this|[A-Za-z_$0-9]+)"
    r"(?:\.[A-Za-z_$0-9]+)*\.isGoogleInternal")
IDE_PATCHED_RE = re.compile(r"resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*true")


# -- ide main.js (vezlin tolerant regex + QNIX single-replace) --
IDE_STOCK_RE = re.compile(
    r"(resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*)(?:this|[A-Za-z_$0-9]+)"
    r"(?:\.[A-Za-z_$0-9]+)*\.isGoogleInternal")
IDE_PATCHED_RE = re.compile(r"resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*true")


# --------------------------------------- signature packs + learn ---

def _hex_pack(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def _hex_parse(s: str) -> tuple[bytes, tuple[int, ...]]:
    """'80 78 ?? 00' -> (b'\x80\x78\x00\x00', (2,)) — маски wildcard."""
    fixed = bytearray()
    wild = []
    for i, tok in enumerate(s.split()):
        if tok in ("??", "?", "..", "."):
            fixed.append(0)
            wild.append(i)
        else:
            fixed.append(int(tok, 16))
    return bytes(fixed), tuple(wild)


def _state_dir() -> Path:
    """Каталог состояния: рядом со скриптом (один вид у Store- и Win32-процессов).
    Roaming у Microsoft Store Python виртуализируется — для learned-шаблонов
    это даёт рассинхрон вида между powershell и python, поэтому только fallback."""
    here = Path(__file__).resolve().parent
    probe = here / ".agy-write-test"
    try:
        probe.write_bytes(b"1")
        probe.unlink()
        return here
    except OSError:
        return daemon_dir()


def _state_path(name: str) -> Path:
    p = _state_dir() / name
    if not p.exists():
        # разовая миграция со старого места (Roaming): забираем уже выученное
        old = daemon_dir() / name
        try:
            if old.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(old, p)
        except OSError:
            pass
    return p


def _local_pack_path() -> Path:
    return _state_path("signatures.local.json")


def _pack_template_for_gate(name: str):
    """Заводской шаблон гейта: (template_bytes, volatile_offsets)."""
    if name == "mgr_x64_auth":
        t = bytes([0x80, 0x78, 0x08, 0x00, 0x74, 0x00, 0x48, 0x8B, 0x00,
                   0x24, 0x00, 0x48, 0x89, 0x00, 0x60])
        return t, (5, 8, 10, 13)
    if name == "mgr_x64_elig":
        t = bytes(b if b is not None else 0 for b in ELIG_ORIG)
        vol = tuple(i for i, b in enumerate(ELIG_ORIG) if b is None)
        return t, vol
    if name == "cli_x64":
        t = bytes([0x48, 0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0,
                   0x80, 0x78, 0x08, 0x00, 0x0F, 0x85, 0, 0, 0, 0])
        return t, (5, 6, 7, 8, 15, 16, 17, 18)
    return None, ()


def _load_local_templates() -> dict:
    try:
        import json
        p = _local_pack_path()
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d.get("format") == SIGPACK_FORMAT:
                return d.get("gates", {})
    except (OSError, ValueError):
        pass
    return {}


def _save_local_templates(gates: dict) -> Path:
    import json
    p = _local_pack_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    prev = p.with_suffix(".prev.json")
    try:
        if p.exists():
            shutil.copy2(p, prev)
    except OSError:
        pass
    p.write_text(json.dumps({"format": SIGPACK_FORMAT, "gates": gates},
                            indent=1, sort_keys=True), encoding="utf-8")
    return p


def _score_window(window: bytes, template: bytes, volatile) -> float:
    """Доля совпавших фиксированных байтов (0..1)."""
    vol = set(volatile)
    n = den = 0
    for i in range(min(len(window), len(template))):
        if i in vol:
            continue
        den += 1
        if window[i] == template[i]:
            n += 1
    return (n / den) if den else 0.0


def _in_ranges(off: int, ln: int, ranges) -> bool:
    return any(rs <= off and off + ln <= re_ for rs, re_ in ranges)


def learn_enum_mgr_auth(data: bytes, ranges):
    """Relaxed-кандидаты hasValidAuth: cmp byte[.+8],0 + short-jcc + mov-тейл."""
    out = []
    for rs, re_ in ranges:
        pos = data.find(b"\x80\x78\x08\x00", rs, re_)
        while pos != -1:
            win = data[pos:pos + 28]
            if len(win) >= 6 and 0x70 <= win[4] <= 0x7F:
                tail = win[5:26]
                i1 = tail.find(b"\x48\x8b")
                if i1 != -1 and len(tail) > i1 + 4 and tail[i1 + 3] == 0x24:
                    rest = tail[i1 + 5:]
                    i2 = rest.find(b"\x48\x89")
                    # ModRM mod=01 rm=000 ([reg+disp8]), reg любое: (b & 0xC7) == 0x40
                    if i2 != -1 and len(rest) > i2 + 2 and (rest[i2 + 2] & 0xC7) == 0x40:
                        out.append(pos)
            pos = data.find(b"\x80\x78\x08\x00", pos + 1, re_)
    return out


def learn_enum_mgr_elig(data: bytes, ranges):
    """Relaxed-кандидаты eligibility: test rax,rax ... mov r10-стек ... test r10,r10."""
    out = []
    for rs, re_ in ranges:
        pos = data.find(b"\x48\x85\xc0", rs, re_)
        while pos != -1:
            win = data[pos:pos + 64]
            for k in range(0, 48):
                if (win[k:k + 4] == b"\x4c\x8b\x94\x24" and len(win) > k + 7
                        and win[k + 5:k + 8] == b"\x00\x00\x00"
                        and b"\x4d\x85\xd2" in win[k:k + 32]):
                    out.append(pos)
                    break
            pos = data.find(b"\x48\x85\xc0", pos + 1, re_)
    return out


def learn_enum_cli_x64(data: bytes, ranges):
    out = []
    for rs, re_ in ranges:
        pos = data.find(b"\x48\x85\xc0", rs, re_)
        while pos != -1:
            win = data[pos:pos + 24]
            if (len(win) >= 19 and win[3] == 0x0F and win[4] in (0x84, 0x85)
                    and win[9:13] == b"\x80\x78\x08\x00"
                    and len(win) > 14 and win[13] == 0x0F and win[14] in (0x84, 0x85)):
                out.append(pos)
            pos = data.find(b"\x48\x85\xc0", pos + 1, re_)
    return out


def learn_rank(data: bytes, cands, template: bytes, volatile, ctx=64):
    scored = []
    for c in cands:
        win = data[c:c + len(template)]
        if len(win) < len(template):
            continue
        scored.append((_score_window(win, template, volatile), c))
    scored.sort(reverse=True)
    return scored


def _ctx_hex(data: bytes, off: int, ln=43) -> str:
    return data[off:off + ln].hex(" ")


def cmd_learn(sel: str, explicit: str | None, apply: bool, auto: bool):
    import json
    targets: dict[str, Path] = {}
    if explicit:
        targets = {_detect_kind(Path(explicit)): Path(explicit)}
    else:
        t = find_all_targets()
        want = ("manager", "cli", "ide") if sel == "all" else (sel,)
        for k in want:
            p = t.get(k)
            if p is not None:
                targets[k] = p
    if not targets:
        print("[!] цели не найдены (попробуй --path PATH)")
        return 2
    stored = _load_local_templates()
    rc = 0
    for kind, path in targets.items():
        print(f"[*] learn {kind}: {path}")
        if kind == "ide":
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as e:
                print(f"    read-error: {e}")
                rc = 1
                continue
            sites = [(m.start(), m.group(0)[-60:]) for m in
                     re.finditer(r"\.isGoogleInternal", text)]
            print(f"    сайтов .isGoogleInternal: {len(sites)}")
            for i, (off, tail) in enumerate(sites[:10]):
                ctx = text[max(0, off - 80):off + 20].replace("\n", " ")
                print(f"    [{i}] @{off}: ...{ctx[-100:]}")
            if len(sites) != 1:
                print("    [!] вхождений != 1 — авто-патч отказан, выбери вручную")
                rc = 1
                continue
            if apply or auto or _confirm("    применить замену этого вхождения на ',true'? [y/N] "):
                res = do_patch_ide(path)
                print(f"    -> {res}")
                if res not in ("patched", "already-patched"):
                    rc = 1
            continue
        # бинарные цели
        try:
            data = path.read_bytes()
            ranges, arch = exec_info(path)
        except OSError as e:
            print(f"    read-error: {e}")
            rc = 1
            continue
        if kind == "manager":
            jobs = [("mgr_x64_auth", learn_enum_mgr_auth),
                    ("mgr_x64_elig", learn_enum_mgr_elig)]
        else:
            jobs = [("cli_x64", learn_enum_cli_x64)]
        for gname, enum in jobs:
            cands = enum(data, ranges)
            if gname == "mgr_x64_elig":
                # enum отдаёт якорь test rax,rax (+6 от старта гейта) — сдвигаем к старту,
                # окно скоринга и применение фиксов идут от старта гейта
                cands = [c - 6 for c in cands if c >= 6 and _in_ranges(c - 6, len(ELIG_ORIG), ranges)]
            template, volatile, src = _effective_template(gname)
            ranked = learn_rank(data, cands, template, volatile)
            print(f"    gate {gname} [{src}]: кандидатов {len(ranked)}")
            for score, off in ranked[:6]:
                print(f"      {score:5.1%} @{hex(off)}: {_ctx_hex(data, off, 43)}")
            if not ranked:
                print("    [!] пусто — сборка сильно уехала, нужен разбор вручную")
                rc = 1
                continue
            best, second = ranked[0][0], (ranked[1][0] if len(ranked) > 1 else 0.0)
            if best < 0.80 or (len(ranked) > 1 and best - second < 0.10):
                print("    [!] нет уверенного лидера (нужно >=80% и отрыв >=10%) — применяю только вручную")
                rc = 1
                continue
            off = ranked[0][1]
            print(f"    [ok] лидер @{hex(off)} ({best:.1%})")
            do_it = apply or auto or _confirm("    записать шаблон и пропатчить отсюда? [y/N] ")
            if not do_it:
                continue
            _store_learned(gname, data, off)
            if kind == "manager":
                print(f"    -> {do_unlock(path)} (шаблон версии сохранён в {_local_pack_path()})")
            else:
                print(f"    -> {do_patch_cli(path)} (шаблон версии сохранён)")
    return rc


def _confirm(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes", "д", "да")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def cmd_sigs(op: str, url: str | None, infile: str | None, outfile: str | None):
    import json
    import urllib.request
    if op == "export":
        out = {"format": SIGPACK_FORMAT, "gates": {}}
        for gname in ("mgr_x64_auth", "mgr_x64_elig", "cli_x64"):
            t, vol = _pack_template_for_gate(gname)
            if t:
                out["gates"][gname] = {"template": _hex_pack(t), "volatile": list(vol)}
        text = json.dumps(out, indent=1, sort_keys=True)
        if outfile:
            Path(outfile).write_text(text, encoding="utf-8")
            print(f"[+] записано: {outfile}")
        else:
            print(text)
        return 0
    if op == "import":
        if not infile:
            print("[!] нужен --file pack.json")
            return 2
        d = json.loads(Path(infile).read_text(encoding="utf-8"))
        if d.get("format") != SIGPACK_FORMAT or "gates" not in d:
            print("[!] плохой формат пака")
            return 2
        for gname, e in d["gates"].items():
            _hex_parse(e["template"])
        _save_local_templates(d["gates"])
        print(f"[+] активировано гейтов: {len(d['gates'])} -> {_local_pack_path()}")
        return 0
    if op == "update":
        if not url:
            print("[!] нужен --url https://.../signatures.json")
            return 2
        with urllib.request.urlopen(url, timeout=30) as r:
            d = json.loads(r.read().decode("utf-8"))
        if d.get("format") != SIGPACK_FORMAT or "gates" not in d:
            print("[!] плохой формат пака")
            return 2
        _save_local_templates(d["gates"])
        print(f"[+] обновлено гейтов: {len(d['gates'])}")
        cmd_status(None)
        return 0
    print("[!] sigs: export|import|update")
    return 2


# Покрытие фиксов по индексам шаблона (для скелетной проверки patched).
GATE_COVER = {
    "mgr_x64_auth": frozenset(range(0, 6)),
    "mgr_x64_elig": frozenset(list(range(9, 15)) + [41]),
    "cli_x64": frozenset(range(9, 13)),
}
TMPL_THRESH = 0.85
TMPL_MARGIN = 0.10
AUTH_FIX = b"\xc6\x40\x08\x01\x90\x90"


def _effective_template(gname: str):
    stored = _load_local_templates().get(gname)
    if stored:
        t, _ = _hex_parse(stored["template"])
        return t, tuple(stored.get("volatile", ())), "local"
    t, vol = _pack_template_for_gate(gname)
    return t, vol, "builtin"


def _resolve_by_template(data: bytes, ranges, gname: str, enum_fn):
    """Template-fallback: лучший relaxed-кандидат по скелету >= THRESH с отрывом."""
    tmpl, vol, src = _effective_template(gname)
    if not tmpl:
        return None
    cands = enum_fn(data, ranges)
    if gname == "mgr_x64_elig":
        cands = [c - 6 for c in cands if c >= 6 and _in_ranges(c - 6, len(tmpl), ranges)]
    ranked = learn_rank(data, cands, tmpl, vol)
    if not ranked:
        return None
    best, second = ranked[0][0], (ranked[1][0] if len(ranked) > 1 else 0.0)
    if best >= TMPL_THRESH and (len(ranked) == 1 or best - second >= TMPL_MARGIN):
        return ranked[0][1], f"template-{src}"
    return None


def _skeleton_ok(data: bytes, off: int, tmpl: bytes, vol, cover) -> bool:
    skip = set(vol) | set(cover)
    n = den = 0
    for i in range(len(tmpl)):
        if i in skip or off + i >= len(data):
            continue
        den += 1
        if data[off + i] == tmpl[i]:
            n += 1
    return den > 0 and (n / den) >= TMPL_THRESH


def _state_at_template(data: bytes, off: int, gname: str) -> str:
    """Состояние гейта в позиции template-кандидата: сначала фиксы, потом скелет."""
    if gname == "mgr_x64_auth":
        if data[off:off + 6] == AUTH_FIX:
            return "patched"
    elif gname == "mgr_x64_elig":
        if data[off + ELIG_OFF1:off + ELIG_OFF1 + ELIG_LEN1] == ELIG_FIX1 \
                and data[off + ELIG_OFF2] == ELIG_FIX2:
            return "patched"
    tmpl, vol, _ = _effective_template(gname)
    if _skeleton_ok(data, off, tmpl, vol, GATE_COVER[gname]):
        return "unpatched"
    return "unknown"


def resolve_manager_gates(data: bytes, ranges, arch):
    """{gate: (state, off, via)}. strict в приоритете, дальше local/builtin-template."""
    out = {}
    if arch in (None, "x64"):
        try:
            st, off = MGR_X64_AUTH.state(data, ranges)
            out["auth"] = (st, off, "strict")
        except SigAmbiguous as e:
            out["auth"] = (f"ambiguous:{e}", None, "strict")
        except SigError:
            r = _resolve_by_template(data, ranges, "mgr_x64_auth", learn_enum_mgr_auth)
            if r:
                off, via = r
                out["auth"] = (_state_at_template(data, off, "mgr_x64_auth"), off, via)
        try:
            st, off = ELIG_GATE.state(data, ranges)
            out["elig"] = (st, off, "strict")
        except SigAmbiguous as e:
            out["elig"] = (f"ambiguous:{e}", None, "strict")
        except SigError:
            r = _resolve_by_template(data, ranges, "mgr_x64_elig", learn_enum_mgr_elig)
            if r:
                off, via = r
                out["elig"] = (_state_at_template(data, off, "mgr_x64_elig"), off, via)
    if "auth" not in out and arch in (None, "arm64"):
        try:
            st, off = MGR_ARM64.state(data, ranges)
            out["auth"] = (st, off, "strict-arm64")
        except (SigError, SigAmbiguous):
            pass
    return out


def _store_learned(gname: str, data: bytes, off: int) -> Path:
    """Сохраняет фактические байты одобренного гейта + расширенный volatile."""
    base, base_vol = _pack_template_for_gate(gname)
    win = data[off:off + len(base)]
    extra = {i for i in range(len(base))
             if i not in base_vol and i < len(win) and win[i] != base[i]}
    stored = _load_local_templates()
    stored[gname] = {"template": _hex_pack(win), "volatile": sorted(set(base_vol) | extra),
                     "at": hex(off), "sha8": hashlib.sha256(data).hexdigest()[:8]}
    return _save_local_templates(stored)


def _fixes_for(gname: str):
    if gname == "mgr_x64_auth":
        return MGR_X64_AUTH.fixes
    if gname == "mgr_x64_elig":
        return [(ELIG_OFF1, ELIG_FIX1), (ELIG_OFF2, bytes([ELIG_FIX2]))]
    raise KeyError(gname)


# ------------------------------------------------- exec sections ---

def _read_exact(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError("truncated executable header")
    return data


def _norm_ranges(ranges, fsize):
    clean = []
    for s, e in ranges:
        s, e = max(0, s), min(fsize, e)
        if s < e:
            clean.append((s, e))
    out = []
    for s, e in sorted(clean):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return tuple(out)


def _arch_name(machine: int):
    return {0x8664: "x64", 0xAA64: "arm64", 0x3E: "x64", 0xB7: "arm64",
            0x01000007: "x64", 0x0100000C: "arm64"}.get(machine)


def _pe_info(f, fsize):
    pe = struct.unpack("<I", _read_exact(f, 0x3C, 4))[0]
    if _read_exact(f, pe, 4) != b"PE\0\0":
        raise ValueError("invalid PE signature")
    coff = _read_exact(f, pe + 4, 20)
    arch = _arch_name(struct.unpack_from("<H", coff, 0)[0])
    nsec = struct.unpack_from("<H", coff, 2)[0]
    optsz = struct.unpack_from("<H", coff, 16)[0]
    stab = pe + 24 + optsz
    ranges = []
    for i in range(nsec):
        sec = _read_exact(f, stab + i * 40, 40)
        rsz, roff = struct.unpack_from("<II", sec, 16)
        ch = struct.unpack_from("<I", sec, 36)[0]
        if ch & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            ranges.append((roff, roff + rsz))
    return _norm_ranges(ranges, fsize), arch


def _elf_info(f, fsize):
    ident = _read_exact(f, 0, 16)
    cls, order = ident[4], ident[5]
    endian = "<" if order == 1 else ">" if order == 2 else None
    if endian is None:
        raise ValueError("unknown ELF byte order")
    machine = struct.unpack(endian + "H", _read_exact(f, 18, 2))[0]
    if cls == 2:
        hdr = _read_exact(f, 0, 64)
        phoff = struct.unpack_from(endian + "Q", hdr, 32)[0]
        phesz, phnum = struct.unpack_from(endian + "HH", hdr, 54)
        lay = (0, 4, 8, 32, "I", "I", "Q", "Q")
    elif cls == 1:
        hdr = _read_exact(f, 0, 52)
        phoff = struct.unpack_from(endian + "I", hdr, 28)[0]
        phesz, phnum = struct.unpack_from(endian + "HH", hdr, 42)
        lay = (0, 24, 4, 16, "I", "I", "I", "I")
    else:
        raise ValueError("unknown ELF class")
    to, fo, oo, so, tf, ff, of, sf = lay
    ranges = []
    for i in range(phnum):
        e = _read_exact(f, phoff + i * phesz, phesz)
        t = struct.unpack_from(endian + tf, e, to)[0]
        fl = struct.unpack_from(endian + ff, e, fo)[0]
        off = struct.unpack_from(endian + of, e, oo)[0]
        sz = struct.unpack_from(endian + sf, e, so)[0]
        if t == 1 and fl & 1:  # PT_LOAD + X
            ranges.append((off, off + sz))
    return _norm_ranges(ranges, fsize), _arch_name(machine)


def _macho_slice_info(f, fsize, base, slice_size):
    magic = _read_exact(f, base, 4)
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise ValueError("unsupported Mach-O slice")
    header = _read_exact(f, base, 32)
    arch = _arch_name(struct.unpack_from(endian + "I", header, 4)[0])
    ncmds = struct.unpack_from(endian + "I", header, 16)[0]
    pos, ranges = base + 32, []
    for _ in range(ncmds):
        cmd, cmdsz = struct.unpack(endian + "II", _read_exact(f, pos, 8))
        if cmdsz < 8 or pos + cmdsz > base + slice_size:
            raise ValueError("invalid Mach-O load command")
        if cmd == 0x19:  # LC_SEGMENT_64
            seg = _read_exact(f, pos, cmdsz)
            nsec = struct.unpack_from(endian + "I", seg, 64)[0]
            if 72 + nsec * 80 > cmdsz:
                raise ValueError("invalid Mach-O section table")
            sp = 72
            for _ in range(nsec):
                sec = seg[sp:sp + 80]
                sname = sec[:16].split(b"\0", 1)[0]
                gname = sec[16:32].split(b"\0", 1)[0]
                size = struct.unpack_from(endian + "Q", sec, 40)[0]
                off = struct.unpack_from(endian + "I", sec, 48)[0]
                flags = struct.unpack_from(endian + "I", sec, 64)[0]
                is_code = ((gname, sname) == (b"__TEXT", b"__text")
                           or flags & (0x80000000 | 0x00000400))
                if is_code:
                    ranges.append((base + off, base + off + size))
                sp += 80
        pos += cmdsz
    return _norm_ranges(ranges, fsize), arch


def _macho_executable_info(f, fsize):
    magic = _read_exact(f, 0, 4)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return _macho_slice_info(f, fsize, 0, fsize)
    fat = {b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
           b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True)}.get(magic)
    if not fat:
        raise ValueError("unsupported Mach-O header")
    endian, is64 = fat
    count = struct.unpack(endian + "I", _read_exact(f, 4, 4))[0]
    esz = 32 if is64 else 20
    ranges, arches = [], []
    for i in range(count):
        e = _read_exact(f, 8 + i * esz, esz)
        if is64:
            off, sz = struct.unpack_from(endian + "QQ", e, 8)
        else:
            off, sz = struct.unpack_from(endian + "II", e, 8)
        sr, sa = _macho_slice_info(f, fsize, off, sz)
        ranges += sr
        arches.append(sa)
    arch = arches[0] if arches and arches[0] and all(a == arches[0] for a in arches) else None
    return _norm_ranges(ranges, fsize), arch


def exec_info(path: Path):
    """(ranges, arch) кодовых секций PE/ELF/Mach-O. При неудаче — весь файл, arch None."""
    try:
        with path.open("rb") as f:
            fsize = os.fstat(f.fileno()).st_size
            magic = _read_exact(f, 0, min(4, fsize))
            if magic[:2] == b"MZ":
                return _pe_info(f, fsize)
            if magic == b"\x7fELF":
                return _elf_info(f, fsize)
            if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                         b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                         b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
                return _macho_executable_info(f, fsize)
    except (OSError, ValueError, struct.error):
        pass
    try:
        return ((0, path.stat().st_size), None)
    except OSError:
        return ((0, 0), None)


# --------------------------------------------------- discovery ---

def _dedup(paths):
    seen, out = set(), []
    for p in paths:
        if p and p.exists():
            try:
                k = os.path.normcase(str(p.resolve()))
            except OSError:
                k = str(p)
            if k not in seen:
                seen.add(k)
                out.append(p)
    out.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return out


def _win_roots():
    out = []
    for v in ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramData", "APPDATA"):
        p = os.environ.get(v)
        if not p:
            continue
        out.append(Path(p))
        if (Path(p) / "Programs").is_dir():
            out.append(Path(p) / "Programs")
    up = os.environ.get("USERPROFILE", "")
    if up:
        out.append(Path(up) / "scoop" / "apps")
    sc = os.environ.get("SCOOP", "")
    if sc:
        out.append(Path(sc) / "apps")
    if sys.platform.startswith("win"):
        try:
            import winreg
            for hive, sub in (
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            ):
                try:
                    with winreg.OpenKey(hive, sub) as key:
                        n = winreg.QueryInfoKey(key)[0]
                        for i in range(n):
                            try:
                                with winreg.OpenKey(key, winreg.EnumKey(key, i)) as s:
                                    try:
                                        disp, _ = winreg.QueryValueEx(s, "DisplayName")
                                    except OSError:
                                        continue
                                    if disp and "antigravity" in str(disp).lower():
                                        try:
                                            loc, _ = winreg.QueryValueEx(s, "InstallLocation")
                                            if loc:
                                                out.append(Path(loc))
                                        except OSError:
                                            pass
                            except OSError:
                                pass
                except OSError:
                    pass
        except ImportError:
            pass
    return [p for p in out if p.is_dir()]


def find_manager_bins() -> list[Path]:
    rel = Path("resources") / "bin" / ("language_server.exe" if os.name == "nt" else "language_server")
    cands: list[Path] = []
    w = shutil.which("language_server")
    if w:
        cands.append(Path(w))
    if os.name == "nt":
        for root in _win_roots():
            cands += [Path(p) for p in __import__("glob").glob(str(root / "*ntigravity*" / rel))]
            cands += [Path(p) for p in __import__("glob").glob(str(root / "*ntigravity*" / "*" / rel))]
            d = root / rel
            if d.is_file():
                cands.append(d)
    else:
        home = Path.home()
        roots = [Path("/opt"), Path("/usr/share"), Path("/usr/lib"),
                 Path("/usr/local/share"), home / ".local" / "share"]
        if sys.platform == "darwin":
            roots += [Path("/Applications"), home / "Applications"]
            mac_rel = Path("Contents") / "Resources" / "bin" / "language_server"
            mac_rel2 = Path("Contents") / "resources" / "bin" / "language_server"
            for root in roots:
                if not root.is_dir():
                    continue
                cands += [Path(p) for p in __import__("glob").glob(str(root / "*ntigravity*.app" / mac_rel))]
                cands += [Path(p) for p in __import__("glob").glob(str(root / "*ntigravity*.app" / mac_rel2))]
        for root in roots:
            if not root.is_dir():
                continue
            cands += [Path(p) for p in __import__("glob").glob(str(root / "*ntigravity*" / rel))]
    return _dedup(cands)


def find_cli_bins() -> list[Path]:
    name = "agy.exe" if os.name == "nt" else "agy"
    cands: list[Path] = []
    w = shutil.which("agy")
    if w:
        cands.append(Path(w))
    if os.name == "nt":
        for root in _win_roots():
            import glob as _g
            cands += [Path(p) for p in _g.glob(str(root / "agy" / "bin" / "agy.exe"))]
            cands += [Path(p) for p in _g.glob(str(root / "agy" / "*" / "bin" / "agy.exe"))]
            cands += [Path(p) for p in _g.glob(str(root / "agy*" / "agy.exe"))]
    else:
        home = Path.home()
        for d in (home / ".local" / "bin", home / "bin",
                  Path("/usr/local/bin"), Path("/usr/bin"), Path("/opt/antigravity/bin")):
            if (d / "agy").is_file():
                cands.append(d / "agy")
        loc = Path.cwd() / "agy"
        if loc.is_file():
            cands.append(loc)
    return _dedup(cands)


def find_ide_mains() -> list[Path]:
    rel = (Path("resources") / "app" / "out" / "main.js" if os.name == "nt"
           else Path("Contents") / "Resources" / "app" / "out" / "main.js"
           if sys.platform == "darwin"
           else Path("resources") / "app" / "out" / "main.js")
    cands: list[Path] = []
    if os.name == "nt":
        for root in _win_roots():
            import glob as _g
            cands += [Path(p) for p in _g.glob(str(root / "*ntigravity*" / rel))]
            cands += [Path(p) for p in _g.glob(str(root / "*ntigravity*" / "*" / rel))]
    else:
        home = Path.home()
        roots = [Path("/opt"), Path("/usr/share"), Path("/usr/lib"), home / ".local" / "share"]
        if sys.platform == "darwin":
            roots += [Path("/Applications"), home / "Applications"]
        for root in roots:
            if not root.is_dir():
                continue
            import glob as _g
            cands += [Path(p) for p in _g.glob(str(root / "*ntigravity*" / rel))]
            if sys.platform == "darwin":
                cands += [Path(p) for p in _g.glob(
                    str(root / "*ntigravity*.app" / "Contents" / "Resources" / "app" / "out" / "main.js"))]
                cands += [Path(p) for p in _g.glob(
                    str(root / "*ntigravity*.app" / "Contents" / "resources" / "app" / "out" / "main.js"))]
    return _dedup(cands)


def find_all_targets():
    mgr = find_manager_bins()
    cli = find_cli_bins()
    ide = find_ide_mains()
    return {
        "manager": mgr[0] if mgr else None,
        "cli": cli[0] if cli else None,
        "ide": ide[0] if ide else None,
        # алиас из v1
        "app": mgr[0] if mgr else None,
    }


# ----------------------------------------------------- scan ---

def scan_manager(path: Path):
    """Статус менеджера по двум гейтам: patched|unpatched|partial-*|unknown."""
    try:
        data = path.read_bytes()
    except OSError:
        return ("not-found", {}, {})
    try:
        ranges, arch = exec_info(path)
    except (OSError, ValueError):
        return ("unknown", {}, {})
    if not ranges or ranges == ((0, 0),):
        return ("unknown", {}, {})
    resolved = resolve_manager_gates(data, ranges, arch)
    results = {k: (v[0], v[1]) for k, v in resolved.items()}
    if not results:
        return ("unknown", {}, {})
    states = {v[0] for v in results.values()}
    if states == {"patched"}:
        return ("patched", results, {})
    if states == {"unpatched"}:
        return ("unpatched", results, {})
    if "patched" in states or "unpatched" in states:
        return ("partial-" + "+".join(f"{k}={v[0]}" for k, v in sorted(results.items())),
                results, {})
    return ("unknown", {}, {})


def scan_cli(path: Path):
    try:
        data = path.read_bytes()
    except OSError:
        return ("not-found", {}, {})
    try:
        ranges, arch = exec_info(path)
    except (OSError, ValueError):
        return ("unknown", {}, {})
    cands = [CLI_X64_V2, CLI_X64_V1, CLI_ARM64] if arch in (None, "x64") else [CLI_ARM64]
    if arch == "arm64":
        cands = [CLI_ARM64]
    for g in cands:
        if g.arch is not None and arch is not None and g.arch != arch:
            continue
        try:
            st, off = g.state(data, ranges)
            return (st, {"cli": (st, off, g)}, {})
        except (SigError, SigAmbiguous):
            continue
    return ("unknown", {}, {})


def scan_ide(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ("not-found", {}, {})
    o = list(IDE_STOCK_RE.finditer(text))
    p = list(IDE_PATCHED_RE.finditer(text))
    if o and p:
        return ("partial-stock+patched", {}, {})
    if o and not p:
        return ("unpatched", {"ide": ("unpatched", o[0].start())}, {})
    if p and not o:
        return ("patched", {"ide": ("patched", p[0].start())}, {})
    return ("unknown", {}, {})


def scan_file(path: Path):
    """Совместимость с v1: для language_server — scan_manager, иначе unknown."""
    if not path.exists():
        return ("not-found", [], [])
    n = path.name.lower()
    if "language_server" in n:
        st, res, _ = scan_manager(path)
        if st == "patched":
            return ("patched", [], [1])
        if st == "unpatched":
            return ("unpatched", [1], [])
        return (st, [], [])
    return ("unknown", [], [])


# -------------------------------------------------- patch ---

def sha8(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:8]


def backup_path_for(target: Path) -> Path:
    return target.with_name(target.name + ".agybak")


def _ensure_backup(target: Path) -> str | None:
    """Создаёт/обновляет .agybak. Возвращает None или текст ошибки."""
    bp = backup_path_for(target)
    try:
        if bp.exists():
            a = sha8(bp)
            b = sha8(target)
            if a == b:
                return None
            prev = target.with_name(target.name + ".agybak.prev")
            try:
                if prev.exists():
                    prev.unlink()
            except OSError:
                pass
            try:
                bp.rename(prev)
            except OSError:
                pass
            shutil.copy2(target, bp)
            return None
        shutil.copy2(target, bp)
        return None
    except OSError as e:
        import errno as _errno
        if sys.platform == "darwin" and getattr(e, "errno", None) in (_errno.EPERM, _errno.EACCES):
            if _mac_ensure_writable(target):
                try:
                    shutil.copy2(target, bp)
                    return None
                except OSError as e2:
                    print(f"    [macos] {_mac_sudo_hint(target)}")
                    return f"backup-error: {e2}"
            print(f"    [macos] {_mac_sudo_hint(target)}")
        return f"backup-error: {e}"


def _locked_win(path: Path) -> bool:
    """True, если файл занят другим процессом (только Windows; на POSIX замена атомарна)."""
    if not sys.platform.startswith("win"):
        return False
    try:
        with path.open("r+b"):
            return False
    except OSError:
        return True


def _mac_run(cmd: list[str]) -> tuple[int, str]:
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=120)
        return r.returncode, ((r.stdout or "") + (r.stderr or ""))[-1000:]
    except (OSError, ValueError) as e:
        return 127, str(e)


def _mac_app_bundle(path: Path):
    """Ближайший *.app выше файла (или None)."""
    try:
        cur = path.resolve().parent
    except OSError:
        return None
    while True:
        if cur.name.endswith(".app") and (cur / "Contents").is_dir():
            return cur
        parent = cur.parent
        if parent == cur:
            return None
        cur = parent


def _mac_ensure_writable(path: Path) -> bool:
    """Снимает uchg-флаг (причина EPERM внутри .app). True если теперь пишется."""
    rc, _ = _mac_run(["chflags", "nouchg", str(path)])
    if rc != 0:
        return False
    try:
        with path.open("r+b"):
            return True
    except OSError:
        return False


def _mac_sudo_hint(path: Path) -> str:
    return (f"macOS blocked writing {path}. Close the app, then either "
            f"re-run with sudo or clear flags first: "
            f"sudo chflags -R nouchg {str(_mac_app_bundle(path) or path)}")


def _mac_write(path: Path, data: bytes):
    """Запись с одной попыткой через chflags на macOS. None ок, иначе текст ошибки."""
    try:
        path.write_bytes(data)
        return None
    except OSError as e:
        import errno as _errno
        if sys.platform == "darwin" and getattr(e, "errno", None) in (_errno.EPERM, _errno.EACCES):
            if _mac_ensure_writable(path):
                try:
                    path.write_bytes(data)
                    return None
                except OSError as e2:
                    print(f"    [macos] {_mac_sudo_hint(path)}")
                    return f"write-error: {e2}"
            print(f"    [macos] {_mac_sudo_hint(path)}")
        return f"write-error: {e}"


def _mac_finalize(path: Path):
    """Переподпись после патча: иначе macOS убьёт бинарь (SIGKILL/Gatekeeper)."""
    if sys.platform != "darwin":
        return
    target = _mac_app_bundle(path) or path
    _mac_run(["xattr", "-dr", "com.apple.quarantine", str(target)])
    rc, out = _mac_run(["codesign", "--force", "--deep", "--sign", "-", str(target)])
    if rc == 0:
        print(f"    [macos] re-signed {target.name}")
    else:
        print(f"    [macos] codesign failed (app may not launch): {out[-300:]}")


def _apply_fixes(data: bytes, off: int, fixes) -> bytes:
    ba = bytearray(data)
    for delta, blob in fixes:
        ba[off + delta: off + delta + len(blob)] = blob
    return bytes(ba)


def do_unlock(target_path: Path, if_needed: bool = False) -> str:
    st, res, _ = scan_manager(target_path)
    if st == "not-found":
        return "not-found"
    if st == "patched":
        return "already-patched"
    if st.startswith(("ambiguous", "unknown")):
        return f"pattern-not-found:{st}"
    # partial или unpatched — патчим все unpatched-гейты
    if st not in ("unpatched",) and not st.startswith("partial"):
        return f"pattern-not-found:{st}"
    try:
        data = target_path.read_bytes()
        ranges, arch = exec_info(target_path)
    except OSError as e:
        return f"read-error: {e}"
    resolved = resolve_manager_gates(data, ranges, arch)
    jobs = []
    arm_fixes = None
    if "auth" in resolved and resolved["auth"][0] == "unpatched":
        off = resolved["auth"][1]
        via = resolved["auth"][2]
        if "arm64" in str(via):
            arm_fixes = MGR_ARM64.fixes
            jobs.append((off, arm_fixes, "hasValidAuth (arm64)"))
        else:
            jobs += [(off, [(d, b)], f"hasValidAuth ({via})") for d, b in _fixes_for("mgr_x64_auth")]
    if "elig" in resolved and resolved["elig"][0] == "unpatched":
        off = resolved["elig"][1]
        jobs += [(off, [(d, b)], f"eligibility ({resolved['elig'][2]})") for d, b in _fixes_for("mgr_x64_elig")]
    if not jobs:
        if if_needed:
            return "already-patched"
        return "pattern-not-found:no-unpatched-gates"
    if _locked_win(target_path):
        return "locked: close Antigravity first (file is busy), then retry"
    err = _ensure_backup(target_path)
    if err:
        return err
    new = data
    for off, fixes, _d in jobs:
        for delta, blob in fixes:
            ba = bytearray(new)
            ba[off + delta: off + delta + len(blob)] = blob
            new = bytes(ba)
    werr = _mac_write(target_path, new)
    if werr:
        return werr
    st2, _, _ = scan_manager(target_path)
    if st2 != "patched":
        return f"verify-failed:{st2}"
    _mac_finalize(target_path)
    return "patched"


def do_patch_cli(target_path: Path) -> str:
    try:
        data = target_path.read_bytes()
        ranges, arch = exec_info(target_path)
    except OSError as e:
        return f"read-error: {e}"
    cands = [CLI_X64_V2, CLI_X64_V1, CLI_ARM64] if arch in (None, "x64") else [CLI_ARM64]
    if arch == "arm64":
        cands = [CLI_ARM64]
    for g in cands:
        if g.arch is not None and arch is not None and g.arch != arch:
            continue
        try:
            s, off = g.state(data, ranges)
        except (SigError, SigAmbiguous) as e:
            last = str(e)
            continue
        if s == "patched":
            return "already-patched"
        if _locked_win(target_path):
            return "locked: close Antigravity CLI first (file is busy), then retry"
        err = _ensure_backup(target_path)
        if err:
            return err
        new = _apply_fixes(data, off, g.fixes)
        werr = _mac_write(target_path, new)
        if werr:
            return werr
        st2 = scan_cli(target_path)[0]
        if st2 != "patched":
            return f"verify-failed:{st2}"
        _mac_finalize(target_path)
        return "patched"
    return f"pattern-not-found:{locals().get('last', 'no-gate-matched')}"


def _ide_cache_dirs():
    home = Path.home()
    if os.name == "nt":
        bases = [Path(os.path.expandvars(r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data")),
                 Path(os.path.expandvars(r"%APPDATA%\Antigravity IDE"))]
    elif sys.platform == "darwin":
        bases = [home / "Library" / "Application Support" / "Antigravity IDE"]
    else:
        cfg = os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")
        bases = [Path(cfg) / "Antigravity IDE"]
    out = []
    for b in bases:
        out += [b / "CachedData", b / "Code Cache" / "js"]
    return out


def do_patch_ide(target_path: Path) -> str:
    try:
        text = target_path.read_text(encoding="utf-8")
    except OSError as e:
        return f"read-error: {e}"
    o = list(IDE_STOCK_RE.finditer(text))
    p = list(IDE_PATCHED_RE.finditer(text))
    if p and not o:
        return "already-patched"
    if not o:
        return "pattern-not-found:ide-gate-missing"
    if len(o) != 1:
        return f"pattern-not-found:ide-gate-count={len(o)}-refusing"
    if _locked_win(target_path):
        return "locked: close Antigravity IDE first (file is busy), then retry"
    err = _ensure_backup(target_path)
    if err:
        return err
    new = IDE_STOCK_RE.sub(lambda m: m.group(1) + "true", text, count=1)
    werr = _mac_write(target_path, new.encode("utf-8"))
    if werr:
        return werr
    for c in _ide_cache_dirs():
        try:
            if c.is_dir():
                shutil.rmtree(c, ignore_errors=True)
        except OSError:
            pass
    if scan_ide(target_path)[0] != "patched":
        return "verify-failed"
    _mac_finalize(target_path)
    return "patched"


def do_restore(target_path: Path) -> str:
    bp = backup_path_for(target_path)
    if not bp.exists():
        if sys.platform.startswith("win"):
            try:
                alt = Path(os.environ.get("LOCALAPPDATA", "")) / "agy-unlock" / "backups"
                if alt.is_dir():
                    cands = list(alt.glob(f"*-{target_path.name}.agybak"))
                    if cands:
                        cands.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                        shutil.copy2(cands[0], target_path)
                        return f"restored-from-alt:{cands[0].name}"
            except OSError as e:
                return f"restore-error: {e}"
        return "no-backup"
    try:
        shutil.copy2(bp, target_path)
    except OSError as e:
        return f"restore-error: {e}"
    return "restored"


# --------------------------------------------------- cli ---

def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} GB"


def _detect_kind(p: Path) -> str:
    """Определяет тип цели по содержимому, а не по имени (копии/кастомные пути)."""
    n = p.name.lower()
    if n.endswith(".js"):
        return "ide"
    try:
        st, _, _ = scan_manager(p)
    except (OSError, ValueError):
        st = "unknown"
    if st not in ("unknown", "not-found") and not st.startswith(("ambiguous", "pattern")):
        return "manager"
    try:
        stc, _, _ = scan_cli(p)
    except (OSError, ValueError):
        stc = "unknown"
    if stc not in ("unknown", "not-found"):
        return "cli"
    # эвристика по имени как fallback
    if "language_server" in n:
        return "manager"
    if "main.js" in n:
        return "ide"
    if n in ("agy", "agy.exe"):
        return "cli"
    # последний шанс: JS-текст
    try:
        t = p.read_text(encoding="utf-8", errors="strict")[:200000]
        if "resetIsTierGCPTos" in t:
            return "ide"
    except (OSError, UnicodeError):
        pass
    return "manager" if p.stat().st_size > 10_000_000 else "cli"


def cmd_status(explicit: str | None = None):
    if explicit:
        p = Path(explicit)
        kind = _detect_kind(p)
        if kind == "ide":
            st, res, _ = scan_ide(p)
        elif kind == "cli":
            st, res, _ = scan_cli(p)
            res = res[1] if isinstance(res, tuple) else res
        else:
            st, res, _ = scan_manager(p)
        size = p.stat().st_size if p.exists() else 0
        print(f"[{TOOL_NAME}] {p}")
        print(f"  статус: {st}  размер: {human_size(size) if size else '-'}")
        if isinstance(res, dict):
            for k, v in res.items():
                print(f"  gate {k}: {v[0]} @ {hex(v[1]) if v[1] is not None else '-'}")
        bp = backup_path_for(p)
        print(f"  бэкап: {'есть' if bp.exists() else 'нет'} ({bp})")
        return
    print(f"{TOOL_NAME} {VERSION}  ({sys.platform})")
    print()
    t = find_all_targets()
    labels = {"manager": "Antigravity 2.0 (language_server)", "cli": "Antigravity CLI (agy)",
              "ide": "Antigravity IDE (main.js)", "app": None}
    for name in ("manager", "cli", "ide"):
        p = t.get(name)
        if p is None:
            print(f"— {labels[name]}: не найдено")
            continue
        if name == "manager":
            st, res, _ = scan_manager(p)
        elif name == "cli":
            st, res, _ = scan_cli(p)
            res = res[1] if isinstance(res, tuple) else res
        else:
            st, res, _ = scan_ide(p)
        size = p.stat().st_size if p.exists() else 0
        bp = backup_path_for(p)
        print(f"— {labels[name]}:")
        print(f"  путь:   {p}")
        print(f"  статус: {st}")
        if isinstance(res, dict):
            for k, v in sorted(res.items()):
                off = v[1] if len(v) > 1 else None
                print(f"    gate {k}: {v[0]}" + (f" @ {hex(off)}" if off is not None else ""))
        print(f"  размер: {human_size(size)}  бэкап: {'есть' if bp.exists() else 'нет'}")
    print()
    print("Подсказка: клиентский патч недостаточен без DNS с подменой гео.")


def resolve_targets(sel: str, explicit: str | None) -> dict[str, Path]:
    if explicit:
        return {"custom": Path(explicit)}
    all_t = {k: v for k, v in find_all_targets().items() if v is not None and k != "app"}
    if sel == "all":
        return all_t
    if sel == "app":
        m = find_all_targets().get("manager")
        return {"manager": m} if m else {}
    if sel in all_t:
        return {sel: all_t[sel]}
    return {}


def cmd_unlock(sel: str, if_needed: bool, explicit: str | None):
    tmap = resolve_targets(sel, explicit)
    if explicit:
        p = Path(explicit)
        kind = _detect_kind(p)
        if kind == "ide":
            print(f"[*] ide: {p}\n    -> {do_patch_ide(p)}")
        elif kind == "cli":
            print(f"[*] cli: {p}\n    -> {do_patch_cli(p)}")
        else:
            print(f"[*] manager: {p}\n    -> {do_unlock(p, if_needed)}")
        return 0
    if not tmap:
        print(f"[!] цель не найдена: {sel} (попробуй --path PATH)")
        return 2
    rc = 0
    for name, path in tmap.items():
        print(f"[*] {name}: {path}")
        if name == "manager":
            res = do_unlock(path, if_needed=if_needed)
        elif name == "cli":
            res = do_patch_cli(path)
        else:
            res = do_patch_ide(path)
        print(f"    -> {res}")
        if res not in ("patched", "already-patched"):
            rc = 1
    return rc


def cmd_restore(sel: str, explicit: str | None):
    if explicit:
        print(f"[*] custom: {explicit}\n    -> {do_restore(Path(explicit))}")
        return 0
    tmap = resolve_targets(sel, explicit)
    if not tmap:
        print(f"[!] цель не найдена: {sel}")
        return 2
    rc = 0
    for name, path in tmap.items():
        print(f"[*] {name}: {path}")
        res = do_restore(path)
        print(f"    -> {res}")
        if not res.startswith(("restored", "restored-from-alt")):
            rc = 1
    return rc


# -------------------------------------------------- daemon ---

def daemon_dir() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(base) / TOOL_NAME
    return Path.home() / f".{TOOL_NAME}"


def daemon_run(poll: float = 5.0, once: bool = False):
    print(f"[*] {TOOL_NAME} daemon: слежу за целями, интервал {poll}с (Ctrl+C — выход)")
    last: dict[str, str] = {}
    while True:
        try:
            t = find_all_targets()
            for name in ("manager", "cli"):
                p = t.get(name)
                if p is None or not p.exists():
                    continue
                try:
                    st = scan_manager(p)[0] if name == "manager" else scan_cli(p)[0]
                except OSError:
                    st = "read-error"
                key = f"{name}:{str(p).lower()}"
                if st in ("unpatched",) or st.startswith("partial"):
                    if last.get(key) != st:
                        print(f"[!] {name} {st}: {p} — патчу…")
                        res = do_unlock(p, True) if name == "manager" else do_patch_cli(p)
                        print(f"    -> {res}")
                elif st.startswith(("unknown", "ambiguous", "pattern")):
                    if last.get(key) != st:
                        print(f"[!] {name}: сигнатуры протухли ({st}) — "
                              f"запусти `{TOOL_NAME} learn {name}`; "
                              f"sha8={sha8(p)} size={p.stat().st_size}")
                last[key] = st
            if once:
                break
            time.sleep(poll)
        except KeyboardInterrupt:
            print("\n[*] daemon остановлен")
            break


def _run_win(cmd: list[str]):
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace")


def _pythonw() -> str:
    py = sys.executable
    if py.lower().endswith("\\python.exe") or py.lower().endswith("/python.exe"):
        pyw = py[: -len("python.exe")] + "pythonw.exe"
        try:
            if Path(pyw).exists():
                return pyw
        except OSError:
            pass
    elif py.lower().endswith(".exe"):
        cand = py[:-4] + "w.exe"
        try:
            if Path(cand).exists():
                return cand
        except OSError:
            pass
    return py


def daemon_install():
    d = daemon_dir()
    d.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve()
    py = sys.executable
    frozen = bool(getattr(sys, "frozen", False))
    if sys.platform.startswith("win"):
        task = TOOL_NAME
        if frozen:
            cmd_run = f'"{py}" daemon run'
            cmd_once = f'"{py}" daemon refresh'
        else:
            pyw = _pythonw()
            cmd_run = f'"{pyw}" "{script}" daemon run'
            cmd_once = f'"{pyw}" "{script}" daemon refresh'
        try:
            _run_win(["schtasks", "/delete", "/tn", task, "/f"])
            r = _run_win(["schtasks", "/create", "/tn", task, "/tr", cmd_run, "/sc", "ONLOGON", "/f"])
            print((r.stdout or "")[-2000:])
            if (r.stderr or "").strip():
                print((r.stderr or "")[-2000:], file=sys.stderr)
            if r.returncode != 0:
                print("[i] ONLOGON не дали, ставлю refresh каждые 30 мин")
                r2 = _run_win(["schtasks", "/create", "/tn", task, "/tr", cmd_once,
                               "/sc", "MINUTE", "/mo", "30", "/f"])
                print((r2.stdout or "")[-2000:])
                return r2.returncode
            print(f"[+] демон установлен: schtasks /tn {task}")
            return 0
        except FileNotFoundError:
            print("[!] schtasks не найден")
            return 1
    elif sys.platform == "darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"com.{TOOL_NAME}.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.{TOOL_NAME}</string>
<key>ProgramArguments</key><array><string>{py}</string><string>{script}</string><string>daemon</string><string>run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>{d}/daemon.log</string>
<key>StandardErrorPath</key><string>{d}/daemon.log</string>
</dict></plist>
""", encoding="utf-8")
        print(f"[+] launchd агент: {plist}\n    запуск: launchctl load {plist}")
        return 0
    unit = Path.home() / ".config" / "systemd" / "user" / f"{TOOL_NAME}.service"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(f"""[Unit]
Description={TOOL_NAME} resident auto re-patch
After=network.target
[Service]
ExecStart={py} {script} daemon run
Restart=always
RestartSec=5
[Install]
WantedBy=default.target
""", encoding="utf-8")
    print(f"[+] systemd unit: {unit}\n    запуск: systemctl --user enable --now {TOOL_NAME}.service")
    return 0


def daemon_uninstall():
    if sys.platform.startswith("win"):
        r = _run_win(["schtasks", "/delete", "/tn", TOOL_NAME, "/f"])
        print(((r.stdout or "") + (r.stderr or ""))[-2000:])
        return r.returncode
    if sys.platform == "darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"com.{TOOL_NAME}.plist"
        try:
            import subprocess
            subprocess.run(["launchctl", "unload", str(plist)], capture_output=True)
        except Exception:
            pass
        try:
            plist.unlink()
            print(f"[-] удалён {plist}")
        except FileNotFoundError:
            print("[i] агент не найден")
        return 0
    unit = Path.home() / ".config" / "systemd" / "user" / f"{TOOL_NAME}.service"
    try:
        unit.unlink()
        print(f"[-] удалён {unit}")
    except FileNotFoundError:
        print("[i] unit не найден")
    return 0


def daemon_status():
    if sys.platform.startswith("win"):
        r = _run_win(["schtasks", "/query", "/tn", TOOL_NAME, "/fo", "LIST", "/v"])
        if r.returncode == 0:
            print("[*] демон: установлен (schtasks)")
            print(((r.stdout or "") + (r.stderr or ""))[-3000:])
        else:
            print("[*] демон: не установлен\n    установка: agy-unlock-analog daemon install")
    elif sys.platform == "darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"com.{TOOL_NAME}.plist"
        print(f"[*] демон: {'установлен' if plist.exists() else 'не установлен'} ({plist})")
    else:
        unit = Path.home() / ".config" / "systemd" / "user" / f"{TOOL_NAME}.service"
        print(f"[*] демон: {'установлен' if unit.exists() else 'не установлен'} ({unit})")


# --------------------------------------------------- tui ---

_C = {"cyan": 36, "green": 32, "yellow": 33, "red": 31, "dim": 90, "bold": 1, "white": 37}


_VT_OK = None


def _ensure_vt() -> bool:
    """Включает Virtual Terminal Processing в conhost (иначе коды видны как текст).
    Возвращает True, если цвета можно использовать."""
    global _VT_OK
    if _VT_OK is not None:
        return _VT_OK
    _VT_OK = True
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            h = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if k32.GetConsoleMode(h, ctypes.byref(mode)):
                k32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            else:
                _VT_OK = False
        except Exception:
            _VT_OK = False
    return _VT_OK


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    return _ensure_vt()


def _c(text: str, *names: str) -> str:
    if not _use_color() or not names:
        return text
    codes = ";".join(str(_C[n]) for n in names if n in _C)
    return f"\x1b[{codes}m{text}\x1b[0m"


def _kv(label: str, value: str, color: str = ""):
    print(f"      {label:<9}{_c(value, color) if color else value}")


def _banner():
    print(_c("Region bypass for Antigravity", "green", "bold"))
    print(_c("Clean - No keys - No telemetry", "green"))
    print("+------------------------------+-------------------------------------+")
    print("| " + _c("Repo", "yellow") + "    " +
          _c("github.com/trustybird/agy-unlock", "white") + "          |")
    print("+------------------------------+-------------------------------------+")


def _clear():
    if not _use_color():
        print()
        return
    os.system("cls" if os.name == "nt" else "clear")


def _read_asar_version(asar: Path):
    """Версия из package.json внутри app.asar (рядом с language_server)."""
    try:
        import json as _json
        with asar.open("rb") as f:
            _u1, header_size, _u2, json_size = struct.unpack("<IIII", f.read(16))
            header = _json.loads(f.read(json_size).decode("utf-8"))
            pkg = header.get("files", {}).get("package.json")
            if not pkg or "offset" not in pkg or "size" not in pkg:
                return None
            f.seek(8 + header_size + int(pkg["offset"]))
            return _json.loads(f.read(int(pkg["size"])).decode("utf-8")).get("version")
    except (OSError, ValueError, KeyError):
        return None


def _asar_for_manager(manager_path: Path):
    parent = manager_path.parent
    for _ in range(4):
        for sub in ("resources/app.asar", "app.asar"):
            p = parent / sub
            if p.is_file():
                return p
        if parent == parent.parent:
            break
        parent = parent.parent
    return None


def _menu_state():
    """Снимок целей для меню: {name: (path|None, status)}."""
    t = find_all_targets()
    out = {}
    for name in ("manager", "cli", "ide"):
        p = t.get(name)
        if p is None:
            out[name] = (None, "not found")
            continue
        if name == "manager":
            st = scan_manager(p)[0]
        elif name == "cli":
            st = scan_cli(p)[0]
        else:
            st = scan_ide(p)[0]
        out[name] = (p, st)
    return out


def _print_menu_panel(state):
    _banner()
    print()
    print("[*] Searching for installations...")
    print("--- ANTIGRAVITY IDE " + "-" * 40)
    p, st = state["ide"]
    _kv("Target:", str(p) if p else "Not found", "cyan" if p else "red")
    _kv("Status:", "found" if p else "not found", "green" if p else "red")
    if p is not None:
        _kv("Patch:", st, "yellow" if st == "patched" else "green")
    print()
    print("--- ANTIGRAVITY 2.0 " + "-" * 40)
    p, st = state["manager"]
    _kv("Target:", str(p) if p else "Not found", "cyan" if p else "red")
    if p is None:
        _kv("Status:", "not found", "red")
    else:
        _kv("Status:", "found", "green")
        _kv("Patch:", st, "yellow" if "patched" in st else "green")
        asar = _asar_for_manager(p)
        ver = _read_asar_version(asar) if asar else None
        _kv("Version:", ver if ver else "not detected", "green" if ver else "yellow")
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        _kv("Size:", human_size(size), "green" if size else "yellow")
    print()
    print("--- ANTIGRAVITY CLI " + "-" * 40)
    p, st = state["cli"]
    _kv("Target:", str(p) if p else "Not found", "cyan" if p else "yellow")
    _kv("Status:", "found" if p else "not found", "green" if p else "yellow")
    if p is not None:
        _kv("Patch:", st, "yellow" if "patched" in st else "green")
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        _kv("Size:", human_size(size), "green" if size else "yellow")
    print()


def _pause():
    try:
        input("  Press Enter to return to menu...")
    except (EOFError, KeyboardInterrupt):
        print()


def _menu_custom_path(state):
    print("--- CUSTOM PATH ---")
    print("1  Manager path   (folder or language_server binary)")
    print("2  CLI path       (agy.exe or folder)")
    print("3  IDE path       (folder or main.js)")
    print("0  Back")
    try:
        ch = input("\n  Select option > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if ch not in ("1", "2", "3"):
        return
    kind = {"1": "manager", "2": "cli", "3": "ide"}[ch]
    try:
        raw = input(f"  {kind} Path > ").strip().strip('"').strip("'")
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not raw:
        return
    p = Path(os.path.abspath(os.path.expanduser(raw)))
    found = None
    if p.is_file():
        found = p
    elif p.is_dir():
        want = {"manager": ("language_server.exe", "language_server"),
                "cli": ("agy.exe", "agy"), "ide": ("main.js",)}[kind]
        for root, _, files in os.walk(p):
            for fn in want:
                if fn in files:
                    found = Path(root) / fn
                    break
            if found or len(root.split(os.sep)) > 8:
                break
            if found:
                break
    if found and found.is_file():
        state[kind] = (found, "custom")
        print(f"  Path updated: {found}")
    else:
        print("  [!] target not found at this path")


def _menu_about():
    print(f"--- ABOUT {TOOL_NAME} {VERSION} ---")
    print("  Removes the Antigravity region block locally:")
    print("  Manager (language_server binary), CLI (agy binary), IDE (main.js).")
    print("  Backups are kept as *.agybak, everything is reversible.")
    print("  Note: a DNS with geo-spoofing is still required,")
    print("  the client patch alone is not enough.")
    print("  Repo: https://github.com/trustybird/agy-unlock")


def interactive(custom=None):
    state = _menu_state()
    if custom:
        for k, v in custom.items():
            if v is not None:
                state[k] = (v, "custom")
    while True:
        _print_menu_panel(state)
        print("--- PATCH " + "-" * 50)
        print("[1]  Antigravity IDE patch   bypass region lock (isGoogleInternal)")
        print("[2]  Antigravity 2.0 patch   patch language_server binary")
        print("[3]  Antigravity CLI patch   unlock agy tool")
        print("[4]  Patch all               everything found")
        print("--- RESTORE " + "-" * 48)
        print("[5]  Antigravity IDE         from backup")
        print("[6]  Antigravity 2.0         from backup")
        print("[7]  Antigravity CLI         from backup")
        print("--- TOOLS " + "-" * 50)
        print("[8]  Daemon install          re-patch automatically after updates")
        print("[9]  Daemon status           check background task")
        print("[10] Learn                   re-discover gates in new builds")
        print("[11] Custom path             override auto-detected target")
        print("[12] About                   info and links")
        print()
        print("[0]  Exit                    quit the patcher")
        print(_c("Tip: patches are reversible - use RESTORE any time.", "dim"))
        try:
            ch = input("\n  Select option > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        print()
        if ch == "0" or ch.lower() in ("q", "quit", "exit"):
            break
        if ch == "":
            continue
        if ch not in {str(i) for i in range(1, 13)}:
            print("[!] Invalid choice")
            _pause()
            continue
        if ch in ("1", "2", "3", "4"):
            if ch == "4":
                cmd_unlock("all", False, None)
            else:
                name = {"1": "ide", "2": "manager", "3": "cli"}[ch]
                p, _ = state.get(name, (None, None))
                if p is None:
                    print(f"[!] {name} not found - use 11 Custom path first")
                elif name == "manager":
                    print(f"[*] {p}\n    -> {do_unlock(p, False)}")
                elif name == "cli":
                    print(f"[*] {p}\n    -> {do_patch_cli(p)}")
                else:
                    print(f"[*] {p}\n    -> {do_patch_ide(p)}")
            state = _menu_state()
            _pause()
            _clear()
        elif ch in ("5", "6", "7"):
            name = {"5": "ide", "6": "manager", "7": "cli"}[ch]
            p, _ = state.get(name, (None, None))
            if p is None:
                print(f"[!] {name} not found - use 11 Custom path first")
            else:
                print(f"[*] {p}\n    -> {do_restore(p)}")
            state = _menu_state()
            _pause()
            _clear()
        elif ch == "8":
            daemon_install()
            _pause()
            _clear()
        elif ch == "9":
            daemon_status()
            _pause()
            _clear()
        elif ch == "10":
            cmd_learn("all", None, apply=False, auto=False)
            state = _menu_state()
            _pause()
            _clear()
        elif ch == "11":
            _menu_custom_path(state)
            _pause()
            _clear()
        elif ch == "12":
            _menu_about()
            _pause()
            _clear()


def main(argv=None):
    if sys.platform.startswith("win"):
        # schtasks отдаёт cp866/cp1251, errors="replace" даёт U+FFFD —
        # без этого print падал бы в cp1251-консоли
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog=TOOL_NAME, description="Analog Antigravity Unlock v2 (manager+cli+ide)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status", help="статус всех целей").add_argument("--path", default=None)
    p_u = sub.add_parser("unlock", help="пропатчить")
    p_u.add_argument("target", nargs="?", default="all", choices=["app", "manager", "cli", "ide", "all"])
    p_u.add_argument("--if-needed", action="store_true")
    p_u.add_argument("--path", default=None)
    p_r = sub.add_parser("restore", help="откатить")
    p_r.add_argument("target", nargs="?", default="all", choices=["app", "manager", "cli", "ide", "all"])
    p_r.add_argument("--path", default=None)
    p_d = sub.add_parser("daemon", help="фоновый автопатч")
    p_d.add_argument("op", nargs="?", default="status", choices=["install", "uninstall", "status", "run", "refresh"])
    p_d.add_argument("--poll", type=float, default=5.0)
    p_l = sub.add_parser("learn", help="переоткрыть гейты в новой сборке (диагностика + шаблоны)")
    p_l.add_argument("target", nargs="?", default="all", choices=["app", "manager", "cli", "ide", "all"])
    p_l.add_argument("--path", default=None)
    p_l.add_argument("--apply", action="store_true", help="сразу применить лучший кандидат")
    p_s = sub.add_parser("sigs", help="паки сигнатур: export|import|update")
    p_s.add_argument("op", nargs="?", default="export", choices=["export", "import", "update"])
    p_s.add_argument("--url", default=None)
    p_s.add_argument("--file", default=None)
    p_s.add_argument("--out", default=None)
    sub.add_parser("prune", help="снять демон")
    sub.add_parser("version", help="версия")
    args = ap.parse_args(argv)
    if args.cmd is None:
        interactive()
        return 0
    if args.cmd == "status":
        cmd_status(args.path)
        return 0
    if args.cmd == "unlock":
        return cmd_unlock(args.target, args.if_needed, args.path)
    if args.cmd == "restore":
        return cmd_restore(args.target, args.path)
    if args.cmd == "daemon":
        if args.op == "install":
            return daemon_install()
        if args.op == "uninstall":
            return daemon_uninstall()
        if args.op == "status":
            daemon_status()
            return 0
        if args.op in ("run", "refresh"):
            daemon_run(poll=args.poll, once=(args.op == "refresh"))
            return 0
    if args.cmd == "prune":
        return daemon_uninstall()
    if args.cmd == "learn":
        tgt = args.target
        return cmd_learn(tgt, args.path, apply=args.apply, auto=False)
    if args.cmd == "sigs":
        return cmd_sigs(args.op, args.url, args.file, args.out)
    if args.cmd == "version":
        print(f"{TOOL_NAME} {VERSION}")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
