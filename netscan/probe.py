"""
probe.py — کاوش عمیق سرویس‌ها روی هر دستگاه زنده.

اصل کار: هر داده‌ای که به‌عنوان «اطلاعات کامل» نمایش داده می‌شود، باید از خود دستگاه
خوانده شده باشد و منبعش ثبت شود. هیچ مقدار حدسی وارد خروجی نمی‌شود.

قابلیت‌ها: HTTP/HTTPS (هدرها، عنوان، سرور)، گواهی TLS، بنر TCP خام (SSH/SMTP/FTP...)،
RTSP، IPP (چاپگر)، SNMP، UPnP description XML، مDNS و NBNS.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import time
import xml.etree.ElementTree as ET
from typing import Any

from . import parsers

UA = "NetScanner/1.0 (+local-admin-tool)"


# ======================================================================================
# TCP banner (SSH، SMTP، FTP، Telnet، ...)
# ======================================================================================
def tcp_banner(ip: str, port: int, timeout: float = 1.5) -> dict[str, Any] | None:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.settimeout(max(0.6, timeout))
        try:
            data = s.recv(2048)
        except socket.timeout:
            # برخی سرویس‌ها اول منتظر ورودی هستند (مثل HTTP/RTSP) — کاوش اختصاصی دارند
            return None
        if not data:
            return None
        text = data.decode("utf-8", errors="replace").strip("\r\n\x00")
        out: dict[str, Any] = {
            "port": port,
            "banner": text[:400],
            "source": f"بنر پروتکل خام روی پورت {port}",
            "certain": True,
        }
        m = re.match(r"^SSH-([\d.]+)-(\S+)", text)
        if m:
            out["protocol"] = "SSH"
            out["ssh_protocol_version"] = m.group(1)
            out["ssh_software"] = m.group(2)
            out["os_hint_from_banner"] = m.group(2)
        elif re.match(r"^220[ -]", text):
            m2 = re.search(r"220[ -](.+)", text)
            if m2 and re.search(r"ftp", text, re.I):
                out["protocol"] = "FTP"
            else:
                out["protocol"] = "SMTP"
            if m2:
                out["smtp_software"] = m2.group(1).strip()[:120]
        return out
    except (OSError, socket.timeout):
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


# ======================================================================================
# HTTP / HTTPS
# ======================================================================================
def _http_request(ip: str, port: int, timeout: float, path: str = "/",
                  method: str = "GET", extra_headers: dict[str, str] | None = None,
                  body: bytes | None = None, use_tls: bool = False,
                  host_header: str | None = None) -> dict[str, Any] | None:
    headers = {
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)
    if host_header:
        headers["Host"] = host_header
    raw = None
    conn = None
    try:
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(65536)
        head = f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode()
        for k, v in resp.getheaders():
            head += f"{k}: {v}\r\n".encode()
        head += b"\r\n"
        parsed = parsers.parse_http_response(head)
        parsed["body"] = raw
        parsed["port"] = port
        parsed["scheme"] = "https" if use_tls else "http"
        return parsed
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def http_probe(ip: str, port: int, timeout: float = 2.0, use_tls: bool = False,
               host_header: str | None = None) -> dict[str, Any] | None:
    r = _http_request(ip, port, timeout, use_tls=use_tls, host_header=host_header)
    if not r:
        return None
    out: dict[str, Any] = {
        "port": port,
        "scheme": r["scheme"],
        "status": r.get("status"),
        "status_text": r.get("status_text"),
        "server": r["headers"].get("server"),
        "powered_by": r["headers"].get("x-powered-by"),
        "www_authenticate": r["headers"].get("www-authenticate"),
        "content_type": r["headers"].get("content-type"),
        "title": parsers.extract_html_title(r.get("body") or b""),
        "source": f"پاسخ HTTP روی پورت {port} (هدرهای واقعی سرور)",
        "certain": True,
        "headers": {k: v for k, v in list(r["headers"].items())[:40]},
    }
    if r["headers"].get("location"):
        out["redirect"] = r["headers"]["location"]
    # برخی دستگاه‌ها نام میزبان/مدل را در meta یا هدرهای سفارشی می‌گذارند
    meta = parsers.parse_html_head_fields(r.get("body") or b"")
    if meta:
        out["html_meta"] = meta
    # فهرست پورتال‌های شناخته‌شده
    portal = None
    for k, v in r["headers"].items():
        if k in ("x-router", "x-device-model", "x-dlink", "x-tp-link", "x-ntgr-uptime",
                 "x-synology-version", "x-firmware-version", "x-mikrotik"):
            portal = f"{k}: {v}"
    if portal:
        out["device_header"] = portal
    return out


def tls_certificate(ip: str, port: int = 443, timeout: float = 3.0,
                    server_name: str | None = None) -> dict[str, Any] | None:
    """خواندن گواهی TLS دستگاه — CN/SAN معمولاً مدل و نام میزبان دقیق را می‌دهد."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        sni = server_name if (server_name and not re.fullmatch(r"[\d.]+", server_name)) else None
        try:
            wrapped = ctx.wrap_socket(s, server_hostname=sni)
        except (ssl.SSLError, ValueError):
            wrapped = ctx.wrap_socket(s, server_hostname=None)
        der = wrapped.getpeercert(binary_form=True)
        info = {
            "port": port,
            "tls_version": wrapped.version(),
            "cipher": (wrapped.cipher() or [None])[0],
            "source": f"گواهی TLS ارائه‌شده توسط خود دستگاه روی پورت {port}",
            "certain": True,
        }
        if der:
            info.update(parsers.parse_x509_certificate(der))
        wrapped.close()
        return info
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def rtsp_probe(ip: str, port: int = 554, timeout: float = 2.0) -> dict[str, Any] | None:
    """اکثر دوربین‌های شبکه در پاسخ OPTIONS نام و نسخهٔ دقیق خود را اعلام می‌کنند."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        req = (f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n"
               f"User-Agent: {UA}\r\n\r\n").encode()
        s.send(req)
        s.settimeout(timeout)
        data = s.recv(4096)
        text = data.decode("latin-1", errors="replace")
        out: dict[str, Any] = {
            "port": port,
            "response": text.split("\r\n\r\n")[0][:600],
            "source": f"پاسخ RTSP روی پورت {port}",
            "certain": True,
        }
        m = re.search(r"Server:\s*(.+)", text, re.I)
        if m:
            out["rtsp_server"] = m.group(1).strip()
        m = re.search(r"Public:\s*(.+)", text, re.I)
        if m:
            out["rtsp_methods"] = m.group(1).strip()
        return out
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def _ipp_payload(operation: int = 0x000B, printer_uri: str | None = None,
                 request_id: int = 1) -> bytes:
    """ساخت بدنهٔ IPP برای Get-Printer-Attributes."""
    attrs = b"\x01"  # operation-attributes-tag
    def _with_name(tag: int, name: str, value: str) -> bytes:
        return bytes([tag]) + len(name).to_bytes(2, "big") + name.encode() + \
               len(value).to_bytes(2, "big") + value.encode()
    attrs += _with_name(0x47, "attributes-charset", "utf-8")
    attrs += _with_name(0x48, "attributes-natural-language", "en")
    if printer_uri:
        attrs += _with_name(0x45, "printer-uri", printer_uri)
    attrs += b"\x03"
    return b"\x01\x01" + operation.to_bytes(2, "big") + request_id.to_bytes(4, "big") + attrs


def ipp_probe(ip: str, port: int = 631, timeout: float = 4.0,
              use_tls: bool = False) -> dict[str, Any] | None:
    """کاوش چاپگر با IPP: مدل دقیق، نام، محل، سریال."""
    uri = f"{'ipps' if use_tls else 'ipp'}://{ip}:{port}/ipp/print"
    body = _ipp_payload(0x000B, uri, int(time.time()) & 0x7FFFFFFF)
    r = _http_request(
        ip, port, timeout, path="/ipp/print", method="POST",
        extra_headers={"Content-Type": "application/ipp"}, body=body, use_tls=use_tls,
        host_header=f"{ip}:{port}",
    )
    if not r or not r.get("body"):
        return None
    ipp = parsers.parse_ipp(r["body"])
    if not ipp.get("attributes"):
        return None
    out: dict[str, Any] = {
        "port": port,
        "ipp": ipp,
        "source": f"پاسخ IPP از چاپگر روی پورت {port} (Get-Printer-Attributes)",
        "certain": True,
    }
    return out


def snmp_probe(ip: str, community: str = "public", timeout: float = 2.0) -> dict[str, Any] | None:
    """SNMP v1 GET — sysDescr/sysName دقیق‌ترین هویت دستگاه را می‌دهد."""
    oids = list(parsers.SNMP_OIDS.keys())
    pkt = parsers.snmp_get_packet(community, oids)
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 161))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(8192)
            except socket.timeout:
                break
            resp = parsers.snmp_parse_response(data, community)
            if not resp.get("values"):
                continue
            named: dict[str, Any] = {}
            for oid, val in resp["values"].items():
                named[parsers.SNMP_OIDS.get(oid, oid)] = val
            return {
                "community": community,
                "values": named,
                "raw_oids": resp["values"],
                "source": "پاسخ SNMP (sysDescr/sysName از خود دستگاه)",
                "certain": True,
            }
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return None


# ======================================================================================
# UPnP / SSDP description XML  — مدل، سازنده و سریال دقیق
# ======================================================================================
_UPNP_FIELDS = (
    "friendlyName", "manufacturer", "manufacturerURL", "modelDescription", "modelName",
    "modelNumber", "modelURL", "serialNumber", "UDN", "UPC", "deviceType", "presentationURL",
)


def fetch_upnp_description(location: str, allowed_hosts: set[str], timeout: float = 3.0) -> dict[str, Any] | None:
    """
    دریافت و تجزیهٔ فایل توصیف UPnP.
    برای امنیت، فقط اگر میزبانِ آدرس داخل همان شبکهٔ اسکن‌شده باشد (SSRF-safe).
    """
    m = re.match(r"^http://([^/:]+)(?::(\d+))?(/.*)?$", location.strip())
    if not m:
        return None
    host, port, path = m.group(1), int(m.group(2) or 80), m.group(3) or "/"
    try:
        host_ip = str(ipaddress.IPv4Address(host))
    except Exception:
        resolved = None
        try:
            resolved = socket.gethostbyname(host)
        except Exception:
            return None
        host_ip = resolved
    if host_ip not in allowed_hosts:
        return None
    if not (1 <= port <= 65535):
        return None
    try:
        conn = http.client.HTTPConnection(host_ip, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": UA, "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            conn.close()
            return None
        raw = resp.read(262144)
        conn.close()
    except Exception:
        return None
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    root = None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    out: dict[str, Any] = {
        "url": location,
        "source": f"فایل توصیف UPnP خوانده‌شده از {location}",
        "certain": True,
        "raw_fields": {},
    }
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        if tag in _UPNP_FIELDS and elem.text and elem.text.strip():
            key = tag[0].lower() + tag[1:]
            out["raw_fields"].setdefault(key, elem.text.strip())
    # سرویس‌های اعلام‌شده
    services = []
    for svc in root.iter():
        if svc.tag.split("}")[-1] == "service":
            st = None
            for ch in svc:
                if ch.tag.split("}")[-1] == "serviceType" and ch.text:
                    st = ch.text.strip()
            if st:
                services.append(st)
    out["services"] = sorted(set(services))[:40]
    out["device"] = out["raw_fields"]
    return out


# ======================================================================================
# خدمات سفارشی روی UDP (SSDP unicast، SNMP، NBNS، mDNS) برای یک میزبان
# ======================================================================================
def ssdp_unicast(ip: str, timeout: float = 1.5) -> dict[str, Any] | None:
    msg = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (ip, 1900))
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            return None
        text = data.decode("latin-1", errors="replace")
        headers = {}
        for line in text.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return {
            "server": headers.get("server"),
            "location": headers.get("location"),
            "st": headers.get("st"),
            "usn": headers.get("usn"),
            "headers": headers,
            "source": "پاسخ SSDP یک‌به‌یک از این دستگاه",
            "certain": True,
        }
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


