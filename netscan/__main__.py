"""
__main__.py — خط فرمان برنامه.

نمونه‌ها:
    python3 -m netscan                       # اسکن خودکار شبکهٔ محلی + گزارش متنی
    python3 -m netscan --target 192.168.1.0/24 --ports common
    python3 -m netscan --html report.html --json result.json
    python3 -m netscan --serve --port 8080   # اجرای رابط وب
    python3 -m netscan --update-oui          # دانلود فهرست رسمی IEEE OUI
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, core, netinfo, report


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    codes = {"green": "\033[92m", "yellow": "\033[93m", "red": "\033[91m",
             "blue": "\033[94m", "dim": "\033[2m", "bold": "\033[1m"}
    return f"{codes.get(color,'')}{text}\033[0m"


def update_oui() -> int:
    """دانلود فهرست رسمی IEEE (oui.csv) برای تشخیص دقیق سازنده."""
    import urllib.request

    url = "https://standards-oui.ieee.org/oui/oui.csv"
    dest = Path(__file__).resolve().parent.parent / "data" / "oui.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"در حال دریافت {url} …")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetScanner/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            data = resp.read()
            f.write(data)
        print(_c(f"ذخیره شد: {dest} ({len(data)/1024:.0f} کیلوبایت)", "green"))
        return 0
    except Exception as e:                                       # noqa: BLE001
        print(_c(f"دانلود ناموفق بود: {e}", "red"))
        print("راه جایگزین: فایل oui.csv را دستی در پوشهٔ data/ قرار دهید "
              "یا بستهٔ nmap را نصب کنید (فایل nmap-mac-prefixes).")
        return 1


def print_report(result: dict) -> None:
    scan = result["scan"]
    print()
    print(_c("═" * 78, "blue"))
    print(_c(f" گزارش اسکن شبکه — {scan['target']}  |  رابط {scan['interface']}  "
             f"|  {scan['duration_sec']} ثانیه", "bold"))
    print(_c("═" * 78, "blue"))
    caps = scan["capabilities"]
    print(f"روش‌های فعال: ARP={'✔' if caps['arp_raw'] else '✘'}  "
          f"ICMP={'✔' if caps['icmp_raw'] else '✘'}  "
          f"TCP-SYN={'✔' if caps['tcp_syn_raw'] else '✘'}  "
          f"root={'✔' if caps['root'] else '✘'}")
    for w in result.get("warnings", []):
        print(_c(f"⚠️  {w}", "yellow"))
    print()
    for d in result["devices"]:
        if d["status"] == "unknown":
            continue
        flags = []
        if d.get("is_gateway"):
            flags.append("دروازه")
        if d.get("is_self"):
            flags.append("همین دستگاه")
        if d.get("mac_is_random"):
            flags.append("MAC تصادفی")
        head = f"● {d['ip']:<15} {d.get('name') or '(بدون نام)'}"
        if flags:
            head += "  [" + ", ".join(flags) + "]"
        print(_c(head, "green" if d["status"] == "online" else "yellow"))
        print(f"   MAC: {d.get('mac') or '—'}   "
              f"سازنده: {d.get('mac_vendor') or 'نامشخص (در ثبت IEEE نبود)'}")
        print(f"   نوع دستگاه: {d.get('device_type') or 'نامشخص'} "
              f"{'' if d.get('device_type_certain', True) else '(استنتاجی) '}"
              f"— مبنا: {d.get('device_type_source') or '—'}")
        ports = d.get("open_tcp_ports") or []
        if ports:
            txt = ", ".join(f"{p['port']}" + (f"/{p['service']}" if p.get("service") else "")
                            for p in ports)
            print(f"   پورت‌های باز: {txt}")
        for f in d.get("facts", [])[:14]:
            mark = "✔" if f["certain"] else "~"
            print(f"   {mark} {f['key']}: {str(f['value'])[:110]}")
            print(_c(f"      منبع: {f['source']}", "dim"))
        for inf in d.get("inferences", []):
            print(_c(f"   ~ {inf['claim']}  (دلیل: {inf['basis']})", "dim"))
        print()
    s = result["summary"]
    print(_c("─" * 78, "blue"))
    print(f"جمع‌بندی: {s['devices_online']} دستگاه | {s['with_mac']} دارای MAC | "
          f"{s['with_hostname']} دارای نام | {s['open_ports_total']} پورت باز")
    if s.get("device_types"):
        print("انواع: " + " | ".join(f"{k}: {v}" for k, v in s["device_types"].items()))
    print(_c("─" * 78, "blue"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="netscan",
        description="اسکنر شبکهٔ داخلی — گزارش دقیق دستگاه‌ها بدون حدس و تخمین",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--target", "-t", default="", help="گسترهٔ هدف: 192.168.1.0/24 یا IP یا بازه")
    ap.add_argument("--interface", "-i", default=None, help="نام رابط شبکه (مثل eth0)")
    ap.add_argument("--ports", choices=["quick", "common", "full", "all"], default="common",
                    help="میزان اسکن پورت (پیش‌فرض: common)")
    ap.add_argument("--ports-plus", default="",
                    help="پورت‌های اضافی، مثلاً 8080,9000-9010 یا 5000,5001")
    ap.add_argument("--mode", choices=["auto", "fast", "full"], default="auto",
                    help="auto: همهٔ لایه‌ها | fast: فقط لایه‌های سریع")
    ap.add_argument("--snmp-community", default="public", help="رشتهٔ community در SNMP")
    ap.add_argument("--no-snmp", action="store_true", help="غیرفعال کردن کاوش SNMP")
    ap.add_argument("--timeout", type=float, default=0.7, help="مهلت اتصال TCP (ثانیه)")
    ap.add_argument("--workers", type=int, default=256, help="تعداد کارهای هم‌زمان")
    ap.add_argument("--host-workers", type=int, default=16, help="کاوش هم‌زمان چند میزبان")
    ap.add_argument("--max-hosts", type=int, default=4096, help="حداکثر تعداد آدرس هدف")
    ap.add_argument("--json", dest="json_out", default=None, help="ذخیرهٔ نتیجه در فایل JSON")
    ap.add_argument("--html", dest="html_out", default=None, help="ذخیرهٔ گزارش در فایل HTML")
    ap.add_argument("--csv", dest="csv_out", default=None, help="ذخیرهٔ خلاصه در فایل CSV")
    ap.add_argument("--update-oui", action="store_true", help="دانلود فهرست رسمی IEEE OUI")
    ap.add_argument("--list-interfaces", action="store_true", help="نمایش رابط‌ها و خروج")
    ap.add_argument("--serve", action="store_true", help="اجرای رابط وب")
    ap.add_argument("--host", default="0.0.0.0", help="آدرس اتصال سرور وب")
    ap.add_argument("--port", type=int, default=8000, help="پورت سرور وب")
    ap.add_argument("--quiet", "-q", action="store_true", help="نمایش ندادن گزارش متنی")
    ap.add_argument("--version", action="version", version=f"NetScanner {__version__}")
    args = ap.parse_args(argv)

    if args.update_oui:
        return update_oui()

    if args.list_interfaces:
        gw = netinfo.get_gateway()
        for i in netinfo.list_interfaces():
            print(f"{i['name']:<12} {str(i.get('mac')):<18} up={i.get('is_up')} "
                  f"ipv4={[a['address'] + '/' + str(a['prefixlen']) for a in i.get('ipv4', [])]}")
        print(f"دروازهٔ پیش‌فرض: {gw}")
        return 0

    if args.serve:
        from .server import serve
        serve(args.host, args.port)
        return 0

    options = {
        "target": args.target,
        "interface": args.interface,
        "ports": args.ports,
        "extra_ports": args.ports_plus,
        "mode": args.mode,
        "snmp": not args.no_snmp,
        "snmp_community": args.snmp_community,
        "tcp_timeout": args.timeout,
        "workers": args.workers,
        "host_workers": args.host_workers,
        "port_workers": args.workers,
        "max_hosts": args.max_hosts,
    }

    last = [0.0]

    def emit(ev: dict) -> None:
        if ev.get("type") == "phase":
            now = time.time()
            if now - last[0] > 0.25:
                last[0] = now
                sys.stderr.write(f"\r\033[2K\033[94m{ev.get('message','')}\033[0m")
                sys.stderr.flush()
        elif ev.get("type") == "log":
            sys.stderr.write("\r\033[2K" + ev.get("message", "") + "\n")
            sys.stderr.flush()
        elif ev.get("type") == "context":
            ctx = ev["context"]
            sys.stderr.write(
                f"هدف: {ctx['target']} ({ctx['host_count']} آدرس) | رابط {ctx['interface']['name']} "
                f"| IP محلی {ctx['local_ip']} | دروازه {ctx['gateway']}\n")

    engine = core.ScanEngine(options, emit)
    try:
        result = engine.run()
    except KeyboardInterrupt:
        print("\nمتوقف شد.", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(_c(f"خطا: {e}", "red"), file=sys.stderr)
        return 2

    sys.stderr.write("\r\033[2K")
    if not args.quiet:
        print_report(result)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        print(f"JSON ذخیره شد: {args.json_out}")
    if args.html_out:
        Path(args.html_out).write_text(report.render_html_report(result), encoding="utf-8")
        print(f"گزارش HTML ذخیره شد: {args.html_out}")
    if args.csv_out:
        import csv
        with open(args.csv_out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["IP", "وضعیت", "نام", "MAC", "سازنده", "نوع دستگاه",
                        "پورت‌های باز", "درگاه", "شواهد"])
            for d in result["devices"]:
                w.writerow([
                    d["ip"], d["status"], d.get("name") or "", d.get("mac") or "",
                    d.get("mac_vendor") or "", d.get("device_type") or "",
                    " ".join(str(p["port"]) for p in d.get("open_tcp_ports", [])),
                    "بله" if d.get("is_gateway") else "خیر", d.get("evidence_count", 0),
                ])
        print(f"CSV ذخیره شد: {args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
