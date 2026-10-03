"""
تست یکپارچه — یک شبکهٔ ساختگی روی localhost می‌سازد و بررسی می‌کند که موتور اسکن
همان چیزهایی را که سرورها واقعاً اعلام می‌کنند گزارش کند (بدون حدس).

اجرا:  python3 tests/test_integration.py
"""

from __future__ import annotations

import http.server
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscan import core                                        # noqa: E402

HTTP_PORT = 18080
HTTPS_PORT = 18443
SERVER_HEADER = "TestRouter/2.1 (Mock)"
PAGE_TITLE = "داشبورد مدیریت روتر تست"
CERT_CN = "Mock Printer M404dn"

OK = "\033[92m✔\033[0m"
FAIL = "\033[91m✘\033[0m"
results: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    results.append((cond, label))
    print(f"{OK if cond else FAIL} {label}")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:                                   # noqa: N802
        body = f"<html><head><title>{PAGE_TITLE}</title></head><body>ok</body></html>".encode()
        self.send_response(200)
        self.send_header("Server", SERVER_HEADER)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:                                  # noqa: N802
        self.do_GET()

    def log_message(self, *a) -> None:                          # noqa: A003
        pass


def make_cert(dirpath: str) -> tuple[str, str]:
    key = os.path.join(dirpath, "k.pem")
    crt = os.path.join(dirpath, "c.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", crt,
         "-days", "3", "-nodes", "-subj", f"/CN={CERT_CN}/O=Mock Devices Inc",
         "-addext", "subjectAltName=DNS:mock-printer.local,IP:127.0.0.1"],
        check=True, capture_output=True)
    return key, crt


def start_servers() -> list:
    servers = []
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    servers.append(httpd)

    key, crt = make_cert(tempfile.mkdtemp())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    httpsd = http.server.ThreadingHTTPServer(("127.0.0.1", HTTPS_PORT), Handler)
    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
    threading.Thread(target=httpsd.serve_forever, daemon=True).start()
    servers.append(httpsd)
    return servers


def main() -> int:
    servers = start_servers()
    options = {
        "target": "127.0.0.1/32",
        "ports": "quick",
        "extra_ports": [HTTP_PORT, HTTPS_PORT],
        "mode": "fast",
        "snmp": False,
        "tcp_timeout": 0.5,
        "workers": 128,
        "host_workers": 4,
        "port_workers": 128,
        "mdns_timeout": 0.8,
        "ssdp_timeout": 0.8,
        "ws_timeout": 0.8,
    }
    result = core.run_scan(options)
    devices = {d["ip"]: d for d in result["devices"]}
    dev = devices.get("127.0.0.1")
    check(dev is not None, "دستگاه 127.0.0.1 کشف شد")
    if dev:
        ports = {p["port"] for p in dev.get("open_tcp_ports", [])}
        check(HTTP_PORT in ports and HTTPS_PORT in ports,
              f"پورت‌های باز {HTTP_PORT} و {HTTPS_PORT} گزارش شدند ({sorted(ports)})")
        facts = {f["key"]: f for f in dev.get("facts", [])}
        server_fact = [f for k, f in facts.items() if "وب‌سرور" in k and str(HTTP_PORT) in k]
        check(bool(server_fact) and SERVER_HEADER in str(server_fact[0]["value"]),
              f"هدر واقعی Server گزارش شد: {server_fact[0]['value'] if server_fact else '—'}")
        title_fact = [f for k, f in facts.items() if "عنوان" in k and str(HTTP_PORT) in k]
        check(bool(title_fact) and PAGE_TITLE == title_fact[0]["value"],
              f"عنوان واقعی صفحه گزارش شد: {title_fact[0]['value'] if title_fact else '—'}")
        cn_fact = [f for k, f in facts.items() if "گواهی TLS" in k]
        check(any(CERT_CN in str(f["value"]) for f in cn_fact),
              f"CN گواهی TLS گزارش شد: {[f['value'] for f in cn_fact]}")
        check(all(f.get("source") for f in dev.get("facts", [])),
              "همهٔ واقعیت‌ها «منبع» دارند (هیچ ادعای بی‌منبعی ثبت نشده)")
        check(dev.get("evidence_count", 0) >= 1, "شواهد زنده‌بودن ثبت شده است")
        check(dev.get("status") == "online", "وضعیت دستگاه «آنلاین» است")
        check(dev.get("device_type_certain") in (True, False), "نوع دستگاه با برچسب قطعیت مشخص شده")
    for srv in servers:
        srv.shutdown()
    failed = [label for ok, label in results if not ok]
    print()
    if failed:
        print(f"\033[91m{len(failed)} بررسی ناموفق:\033[0m")
        for f in failed:
            print("  -", f)
        return 1
    print(f"\033[92mهمهٔ {len(results)} بررسی موفق بود.\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
