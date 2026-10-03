"""
server.py — رابط وب (بدون هیچ وابستگی بیرونی؛ فقط کتابخانهٔ استاندارد پایتون).

مسیرها:
    GET  /                       رابط کاربری
    GET  /static/*               فایل‌های رابط کاربری
    GET  /api/context            رابط‌ها، توانایی‌ها، هدف‌های پیشنهادی
    POST /api/scan               شروع اسکن  →  {{"scan_id": "..."}}
    GET  /api/stream/<id>        رویدادهای زنده (SSE)
    POST /api/stop/<id>          توقف اسکن
    GET  /api/result/<id>        نتیجهٔ کامل JSON
    GET  /api/export/<id>.<fmt>  خروجی JSON / CSV / HTML
    POST /api/oui/update         دانلود فهرست رسمی IEEE
"""

from __future__ import annotations

import csv
import io
import json
import os
import queue
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__, core, netinfo, report

STATIC_DIR = Path(__file__).resolve().parent / "static"
SCANS: dict[str, dict[str, Any]] = {}
SCANS_LOCK = threading.Lock()
ACTIVE_SCAN_ID: str | None = None
MAX_EVENT_BUFFER = 1500


# ======================================================================================
def _context() -> dict[str, Any]:
    ifaces = netinfo.list_interfaces()
    gw = netinfo.get_gateway() or {}
    caps = core.discovery.RawCapabilities()
    suggestions = []
    for i in ifaces:
        if i.get("is_loopback"):
            continue
        for a in i.get("ipv4", []):
            suggestions.append({
                "cidr": a["cidr"], "address": a["address"], "interface": i["name"],
                "mac": i.get("mac"), "is_default_route": gw.get("device") == i["name"],
            })
    from .oui import OuiDatabase
    oui = OuiDatabase()
    return {
        "version": __version__,
        "interfaces": ifaces,
        "gateway": gw,
        "capabilities": caps.as_dict(),
        "suggested_targets": suggestions,
        "oui": {"entries": oui.size, "sources": oui.sources, "fallback_only": oui.is_fallback_only},
        "hostname": netinfo.hostname_of_self(),
        "python": __import__("sys").version.split()[0],
    }


def _start_scan(payload: dict[str, Any]) -> str:
    global ACTIVE_SCAN_ID
    with SCANS_LOCK:
        if ACTIVE_SCAN_ID and not SCANS.get(ACTIVE_SCAN_ID, {}).get("done"):
            raise RuntimeError("یک اسکن در حال اجراست؛ ابتدا آن را متوقف کنید.")
        scan_id = uuid.uuid4().hex[:12]
        entry: dict[str, Any] = {
            "id": scan_id, "events": [], "subscribers": [], "done": False,
            "result": None, "error": None, "cancel": threading.Event(),
            "started": time.time(), "options": {},
        }
        SCANS[scan_id] = entry
        ACTIVE_SCAN_ID = scan_id

    def emit(ev: dict[str, Any]) -> None:
        with SCANS_LOCK:
            st = SCANS.get(scan_id)
            if st is None:
                return
            st["events"].append(ev)
            if len(st["events"]) > MAX_EVENT_BUFFER:
                del st["events"][: len(st["events"]) - MAX_EVENT_BUFFER]
            if ev.get("type") == "done":
                st["done"] = True
                st["result"] = ev.get("result")
            subs = list(st["subscribers"])
        for q in subs:
            try:
                q.put_nowait(ev)
            except Exception:
                pass

    options = {
        "target": str(payload.get("target") or "").strip(),
        "interface": payload.get("interface") or None,
        "ports": payload.get("ports") or "common",
        "extra_ports": payload.get("extra_ports") or "",
        "mode": payload.get("mode") or "auto",
        "snmp": bool(payload.get("snmp", True)),
        "snmp_community": str(payload.get("snmp_community") or "public"),
        "tcp_timeout": float(payload.get("tcp_timeout") or 0.7),
        "udp_timeout": float(payload.get("udp_timeout") or 0.5),
        "workers": int(payload.get("workers") or 256),
        "host_workers": int(payload.get("host_workers") or 16),
        "port_workers": int(payload.get("workers") or 512),
        "max_hosts": int(payload.get("max_hosts") or 4096),
        "mdns_timeout": 2.0,
    }

    def _runner() -> None:
        try:
            engine = core.ScanEngine(options, emit, SCANS[scan_id]["cancel"])
            engine.run()
        except Exception as e:                                   # noqa: BLE001
            emit({"type": "error", "message": f"{type(e).__name__}: {e}"})
            with SCANS_LOCK:
                SCANS[scan_id]["done"] = True
                SCANS[scan_id]["error"] = str(e)
            emit({"type": "done", "result": {"scan": {"error": str(e)}, "devices": [],
                                             "summary": {}, "warnings": [str(e)]}})

    with SCANS_LOCK:
        SCANS[scan_id]["options"] = options
    threading.Thread(target=_runner, name=f"scan-{scan_id}", daemon=True).start()
    return scan_id


# ======================================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = f"NetScanner/{__version__}"
    protocol_version = "HTTP/1.1"

    # ---------------------------- helpers ----------------------------
    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text: str, ctype: str = "text/plain; charset=utf-8", status: int = 200,
              extra: dict[str, str] | None = None) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self._text("یافت نشد", status=404)
            return
        ctype = {
            ".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
        }.get(path.suffix, "application/octet-stream")
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return {}

    def log_message(self, fmt: str, *args: Any) -> None:          # noqa: A003
        if os.environ.get("NETSCAN_HTTP_LOG"):
            super().log_message(fmt, *args)

    # ---------------------------- routes ----------------------------
    def do_GET(self) -> None:                                     # noqa: N802
        path = self.path.split("?")[0]
        try:
            if path in ("/", "/index.html"):
                return self._file(STATIC_DIR / "index.html")
            if path.startswith("/static/"):
                rel = path[len("/static/"):]
                target = (STATIC_DIR / rel).resolve()
                if not str(target).startswith(str(STATIC_DIR.resolve())):
                    return self._text("دسترسی مجاز نیست", status=403)
                return self._file(target)
            if path == "/api/context":
                return self._json(_context())
            if path == "/api/health":
                return self._json({"ok": True, "active_scan": ACTIVE_SCAN_ID})
            if path.startswith("/api/stream/"):
                return self._stream(path.rsplit("/", 1)[-1])
            if path.startswith("/api/result/"):
                sid = path.rsplit("/", 1)[-1]
                with SCANS_LOCK:
                    st = SCANS.get(sid)
                    if st is None:
                        return self._json({"error": "شناسهٔ اسکن یافت نشد"}, 404)
                    return self._json({"done": st["done"], "error": st["error"],
                                       "result": st["result"], "options": st["options"]})
            if path.startswith("/api/export/"):
                return self._export(path.rsplit("/", 1)[-1])
            if path == "/favicon.ico":
                return self._text("", status=204)
            return self._text("یافت نشد", status=404)
        except BrokenPipeError:
            return
        except Exception as e:                                     # noqa: BLE001
            return self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self) -> None:                                    # noqa: N802
        path = self.path.split("?")[0]
        try:
            if path == "/api/scan":
                payload = self._body()
                try:
                    sid = _start_scan(payload)
                except RuntimeError as e:
                    return self._json({"error": str(e)}, 409)
                return self._json({"scan_id": sid})
            if path.startswith("/api/stop/"):
                sid = path.rsplit("/", 1)[-1]
                with SCANS_LOCK:
                    st = SCANS.get(sid)
                    if st is None:
                        return self._json({"error": "شناسهٔ اسکن یافت نشد"}, 404)
                    st["cancel"].set()
                return self._json({"stopped": True})
            if path == "/api/oui/update":
                from .__main__ import update_oui
                rc = update_oui()
                return self._json({"ok": rc == 0})
            return self._text("یافت نشد", status=404)
        except BrokenPipeError:
            return
        except Exception as e:                                     # noqa: BLE001
            return self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    # ---------------------------- SSE ----------------------------
    def _stream(self, scan_id: str) -> None:
        with SCANS_LOCK:
            st = SCANS.get(scan_id)
            if st is None:
                return self._json({"error": "شناسهٔ اسکن یافت نشد"}, 404)
            backlog = list(st["events"])
            q: queue.Queue = queue.Queue()
            st["subscribers"].append(q)
            done = st["done"]
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def _write(ev: dict[str, Any]) -> bool:
            try:
                payload = json.dumps(ev, ensure_ascii=False)
                self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                return True
            except Exception:
                return False

        try:
            for ev in backlog:
                if not _write(ev):
                    return
            if done:
                return
            while True:
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    try:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                    except Exception:
                        return
                    continue
                if not _write(ev):
                    return
                if ev.get("type") == "done":
                    return
        finally:
            with SCANS_LOCK:
                st = SCANS.get(scan_id)
                if st and q in st["subscribers"]:
                    st["subscribers"].remove(q)

    # ---------------------------- export ----------------------------
    def _export(self, token: str) -> None:
        if "." not in token:
            return self._text("قالب نامعتبر", status=400)
        sid, fmt = token.rsplit(".", 1)
        with SCANS_LOCK:
            st = SCANS.get(sid)
        if not st or not st.get("result"):
            return self._text("نتیجه‌ای موجود نیست", status=404)
        result = st["result"]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body = json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")
            return self._download(body, f"netscan-{stamp}.json", "application/json; charset=utf-8")
        if fmt == "html":
            html_text = report.render_html_report(result)
            return self._download(html_text.encode("utf-8"), f"netscan-report-{stamp}.html",
                                  "text/html; charset=utf-8")
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["IP", "وضعیت", "نام", "MAC", "سازنده", "نوع دستگاه", "پورت‌های باز",
                        "درگاه", "شواهد", "استنتاج‌ها"])
            for d in result.get("devices", []):
                w.writerow([
                    d["ip"], d["status"], d.get("name") or "", d.get("mac") or "",
                    d.get("mac_vendor") or "", d.get("device_type") or "",
                    " ".join(str(p["port"]) for p in d.get("open_tcp_ports", [])),
                    "بله" if d.get("is_gateway") else "خیر", d.get("evidence_count", 0),
                    " | ".join(x.get("claim", "") for x in d.get("inferences", [])),
                ])
            return self._download(buf.getvalue().encode("utf-8-sig"),
                                  f"netscan-{stamp}.csv", "text/csv; charset=utf-8")
        return self._text("قالب پشتیبانی نمی‌شود", status=400)

    def _download(self, body: bytes, filename: str, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ======================================================================================
def serve(host: str = "0.0.0.0", port: int = 8000) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    print(f"NetScanner {__version__}")
    print(f"رابط وب روی http://{host}:{port}  (Ctrl+C برای خروج)")
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        print("اجرا با دسترسی root: اسکن ARP/ICMP/TCP-SYN فعال است ✔")
    else:
        print("اجرا بدون دسترسی root: کشف با TCP/UDP/ping انجام می‌شود. "
              "برای نتیجهٔ کامل‌تر: sudo python3 -m netscan --serve")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nخروج.")
    finally:
        httpd.server_close()
