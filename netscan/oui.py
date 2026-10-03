"""
oui.py — تشخیص سازندهٔ کارت شبکه از روی پیشوند MAC (OUI).

منابع به‌ترتیب اولویت:
1. مسیر داده‌شده توسط کاربر (NETSCAN_OUI یا data/oui.csv)
2. فایل رسمی IEEE oui.csv
3. فایل nmap-mac-prefixes
4. فایل‌های بسته‌های سیستم (ieee-data, arp-scan, wireshark manuf)
5. واژه‌نامهٔ کوچک داخلی (فقط به‌عنوان آخرین راه‌حل، با ذکر منبع)

همهٔ این‌ها «ثبت رسمی IEEE» هستند؛ هیچ حدس مشابه‌یابی (fuzzy) انجام نمی‌شود.
"""

from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Any

from .oui_data import FALLBACK_OUI, VIRTUAL_OUI

SYSTEM_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/ieee-data/oui.csv",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/local/etc/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
]


class OuiDatabase:
    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self.table: dict[str, str] = {}
        self.sources: list[str] = []
        self.virtual: dict[str, str] = dict(VIRTUAL_OUI)
        self._loaded_from_fallback = False
        paths: list[str] = []
        env = os.environ.get("NETSCAN_OUI")
        if env:
            paths.append(env)
        if extra_paths:
            paths.extend(extra_paths)
        data_dir = Path(__file__).resolve().parent.parent / "data"
        paths.append(str(data_dir / "oui.csv"))
        paths.extend(SYSTEM_PATHS)
        for p in paths:
            if os.path.exists(p):
                try:
                    self._load_file(p)
                    self.sources.append(p)
                except Exception:
                    continue
            if len(self.table) > 5000:
                break
        if not self.table:
            self.table = dict(FALLBACK_OUI)
            self._loaded_from_fallback = True
            self.sources.append("واژه‌نامهٔ داخلی برنامه (oui_data.py)")

    # ----------------------------------------------------------------------------------
    def _load_file(self, path: str) -> None:
        lower = path.lower()
        if lower.endswith(".csv"):
            with open(path, newline="", errors="replace") as f:
                reader = csv.reader(f)
                header_skipped = False
                for row in reader:
                    if len(row) < 3:
                        continue
                    if not header_skipped and row[0].strip().lower() == "registry":
                        header_skipped = True
                        continue
                    prefix = re.sub(r"[^0-9A-Fa-f]", "", row[1] if len(row) > 1 else "")
                    if len(prefix) == 6:
                        self.table[prefix.upper()] = row[2].strip()
            return
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                if m:
                    self.table[m.group(1).upper()] = m.group(2).strip()
                    continue
                m = re.match(r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})\s+(.*)$", line)
                if m:
                    prefix = (m.group(1) + m.group(2) + m.group(3)).upper()
                    rest = m.group(4)
                    rest = re.sub(r"^\(hex\)\s*", "", rest).strip()
                    if rest:
                        self.table.setdefault(prefix, rest)
                    continue
                m = re.match(r"^([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\s+(.+)$", line)
                if m:
                    self.table.setdefault(m.group(1).replace(":", "").upper(), m.group(2).strip())

    # ----------------------------------------------------------------------------------
    @property
    def size(self) -> int:
        return len(self.table)

    @property
    def is_fallback_only(self) -> bool:
        return self._loaded_from_fallback

    def lookup(self, mac: str | None) -> dict[str, Any]:
        """نتیجهٔ جست‌وجوی OUI همراه با منبع (بدون حدس)."""
        result: dict[str, Any] = {
            "vendor": None,
            "source": None,
            "is_locally_administered": False,
            "is_virtual": False,
            "virtual_kind": None,
            "certain": True,
        }
        if not mac:
            result["certain"] = False
            return result
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) < 12:
            result["certain"] = False
            return result
        prefix = clean[:6]
        second = int(clean[1], 16)
        if second & 0x2:
            result["is_locally_administered"] = True
        if prefix in self.virtual:
            result["is_virtual"] = True
            result["virtual_kind"] = self.virtual[prefix]
        vendor = self.table.get(prefix)
        if vendor:
            result["vendor"] = vendor
            result["source"] = " | ".join(self.sources[:2]) if self.sources else None
            result["certain"] = not self._loaded_from_fallback
        if result["is_locally_administered"] and not result["is_virtual"]:
            result["note"] = (
                "بیت «محلی‌مدیریت‌شده» در MAC روشن است؛ این آدرس یا توسط خود دستگاه "
                "تصادفی ساخته شده (Randomized MAC) یا ویرایش دستی است — پس سازنده در ثبت IEEE نیست."
            )
        if result["is_virtual"]:
            result["vendor"] = result["vendor"] or result["virtual_kind"]
        return result
