"""
parsers.py — تجزیه‌گرهای باینری برای داده‌های دقیقی که از دستگاه‌ها می‌خوانیم.

هر تابع، دادهٔ خام پروتکل را می‌گیرد و فیلدهای واقعی (نه تخمینی) را برمی‌گرداند:

* parse_x509_certificate : گواهی TLS  (CN / SAN / صادرکننده / تاریخ انقضا)
* parse_ipp              : پاسخ IPP  (printer-make-and-model, printer-info, ...)
* parse_dns_packet       : بستهٔ DNS/mDNS (نام میزبان، رکوردهای PTR/SRV/TXT)
* snmp_*                 : کدگذاری/رمزگشایی BER برای SNMP v1/v2c
* parse_dhcp_leases      : فایل‌های اجارهٔ DHCP (dnsmasq / ISC dhcpd / Kea)
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
import struct
from typing import Any


# ======================================================================================
# 1) X.509 / DER  (برای خواندن گواهی TLS)
# ======================================================================================
def _der_read_length(data: bytes, pos: int) -> tuple[int, int]:
    """Return (length, new_pos)."""
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("DER: طول ناخوانا")
    return int.from_bytes(data[pos : pos + n], "big"), pos + n


def _der_parse(data: bytes, pos: int = 0, depth: int = 0) -> tuple[dict[str, Any], int]:
    """Minimal DER tree parser: returns (node, next_pos)."""
    if depth > 24:
        raise ValueError("DER: عمق زیاد")
    tag = data[pos]
    length, pos = _der_read_length(data, pos + 1)
    end = pos + length
    node: dict[str, Any] = {"tag": tag, "len": length, "children": [], "value": None}
    constructed = bool(tag & 0x20)
    if constructed:
        p = pos
        while p < end:
            child, p = _der_parse(data, p, depth + 1)
            node["children"].append(child)
    else:
        node["value"] = data[pos:end]
    return node, end


def _der_find_all(node: dict[str, Any], tag: int) -> list[dict[str, Any]]:
    out = []
    for c in node["children"]:
        if c["tag"] == tag:
            out.append(c)
        out.extend(_der_find_all(c, tag))
    return out


def _oid_to_str(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _der_str(raw: bytes | None) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            pass
    return raw.hex()


_OID_CN = "2.5.4.3"
_OID_O = "2.5.4.10"
_OID_SAN = "2.5.29.17"


def parse_x509_certificate(der: bytes) -> dict[str, Any]:
    """استخراج فیلدهای واقعی گواهی TLS از دادهٔ DER."""
    out: dict[str, Any] = {
        "subject_cn": None,
        "subject_org": None,
        "issuer_cn": None,
        "issuer_org": None,
        "not_before": None,
        "not_after": None,
        "san_dns": [],
        "san_ip": [],
        "fingerprint_sha256": None,
    }
    import hashlib

    out["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    root, _ = _der_parse(der, 0)
    tbs = None
    for c in root["children"]:
        if c["tag"] == 0x30:
            tbs = c
            break
    if tbs is None:
        return out

    def _read_name(node: dict[str, Any]) -> tuple[str | None, str | None]:
        cn = org = None
        for rdn in node["children"]:            # SET
            for atv in rdn["children"]:         # SEQUENCE {OID, value}
                if len(atv["children"]) >= 2 and atv["children"][0]["tag"] == 0x06:
                    oid = _oid_to_str(atv["children"][0]["value"] or b"")
                    val = _der_str(atv["children"][1]["value"])
                    if oid == _OID_CN and cn is None:
                        cn = val
                    elif oid == _OID_O and org is None:
                        org = val
        return cn, org

    idx = 0
    children = tbs["children"]
    if children and children[0]["tag"] == 0xA0:      # version
        idx = 1
    # serial (idx), signature (idx+1), issuer (idx+2), validity (idx+3), subject (idx+4)
    try:
        issuer_node = children[idx + 2]
        validity = children[idx + 3]
        subject_node = children[idx + 4]
        out["issuer_cn"], out["issuer_org"] = _read_name(issuer_node)
        out["subject_cn"], out["subject_org"] = _read_name(subject_node)
        if len(validity["children"]) >= 2:
            out["not_before"] = _der_str(validity["children"][0]["value"])
            out["not_after"] = _der_str(validity["children"][1]["value"])
    except (IndexError, KeyError):
        return out

    # SAN extension
    for ext in _der_find_all(tbs, 0x30):
        kids = ext["children"]
        if len(kids) == 2 and kids[0]["tag"] == 0x06 and kids[1]["tag"] == 0x04:
            if _oid_to_str(kids[0]["value"] or b"") == _OID_SAN:
                try:
                    san_node = _der_parse(kids[1]["value"] or b"")[0]
                    for gn in san_node["children"]:
                        if gn["tag"] == 0x82:      # dNSName
                            out["san_dns"].append(_der_str(gn["value"]))
                        elif gn["tag"] == 0x87:    # iPAddress
                            raw = gn["value"] or b""
                            if len(raw) == 4:
                                out["san_ip"].append(str(ipaddress.IPv4Address(raw)))
                except Exception:
                    pass
    return out


# ======================================================================================
# 2) IPP  (چاپگرها / پرینترهای شبکه)
# ======================================================================================
def _ipp_attr_value(data: bytes, pos: int) -> tuple[str, int]:
    """IPP value-tag aware string read."""
    if pos >= len(data):
        return "", pos
    first = data[pos]
    if first < 0x80:
        length = first
        pos += 1
    else:
        n = first & 0x7F
        length = int.from_bytes(data[pos + 1 : pos + 1 + n], "big")
        pos += 1 + n
    val = data[pos : pos + length]
    return val.decode("utf-8", errors="replace"), pos + length


def parse_ipp(data: bytes) -> dict[str, Any]:
    """
    تجزیهٔ پاسخ IPP (Get-Printer-Attributes).
    کلیدهایی مثل printer-make-and-model، printer-info، printer-location، printer-name
    و همچنین 'ipp-uri' استخراج می‌شوند.
    """
    out: dict[str, Any] = {"attributes": {}}
    if len(data) < 8:
        return out
    pos = 8  # version(2) + status-code(2) + request-id(4)
    out["status_code"] = struct.unpack(">H", data[2:4])[0]
    groups: list[str] = []
    current_group = "operation-attributes"
    while pos < len(data):
        tag = data[pos]
        if tag == 0x03:  # end-of-attributes
            break
        if tag in (0x01, 0x02, 0x04, 0x05):  # delimiter / operation/job/printer groups
            if tag == 0x04:
                current_group = "printer-attributes"
            elif tag == 0x02:
                current_group = "job-attributes"
            elif tag == 0x01:
                current_group = "operation-attributes"
            elif tag == 0x05:
                current_group = "unsupported-attributes"
            groups.append(current_group)
            pos += 1
            continue
        # name
        name, pos = _ipp_attr_value(data, pos)
        if pos >= len(data):
            break
        vtag = data[pos]
        pos += 1
        value, pos = _ipp_attr_value(data, pos)
        # additional values (collections) – skip 1-setOf tags
        while pos < len(data) and data[pos] == 0x00:
            pos += 1
            _, pos = _ipp_attr_value(data, pos)
        if name:
            key = name.strip()
            if vtag in (0x21, 0x22, 0x23):  # integer
                try:
                    val: Any = int(value) if value.isdigit() else value
                except Exception:
                    val = value
            elif vtag == 0x41 or vtag == 0x42 or vtag == 0x44 or vtag == 0x45 or vtag == 0x47:
                val = value
            else:
                continue
            if key in out["attributes"] and out["attributes"][key] != val:
                prev = out["attributes"][key]
                if not isinstance(prev, list):
                    prev = [prev]
                prev.append(val)
                out["attributes"][key] = prev
            else:
                out["attributes"][key] = val
    attrs = out["attributes"]
    for k in ("printer-make-and-model", "printer-info", "printer-name", "printer-location",
              "printer-device-id", "printer-uri-supported", "printer-state-reasons",
              "printer-uuid", "printer-serial-number", "document-format-supported"):
        if k in attrs:
            out[k.replace("-", "_").upper()] = attrs[k]
    return out


# ======================================================================================
# 3) DNS / mDNS
# ======================================================================================
_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 16: "TXT", 33: "SRV", 28: "AAAA"}


def _dns_read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """خواندن یک نام DNS با پشتیبانی از فشرده‌سازی اشاره‌گر (0xC0)."""
    labels: list[str] = []
    next_pos = pos
    jumped = False
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            pos += 1
            if not jumped:
                next_pos = pos
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_pos = pos + 2
            jumped = True
            if depth > 12 or ptr >= len(data):
                break
            inner, _ = _dns_read_name(data, ptr, depth + 1)
            if inner:
                labels.append(inner)
            break
        if pos + 1 + ln > len(data):
            break
        labels.append(data[pos + 1 : pos + 1 + ln].decode("utf-8", errors="replace"))
        pos += 1 + ln
    else:
        if not jumped:
            next_pos = pos
    return ".".join([x for x in labels if x]), next_pos


def parse_dns_packet(data: bytes) -> dict[str, Any]:
    """تجزیهٔ یک بستهٔ DNS/mDNS (پاسخ)."""
    out: dict[str, Any] = {"answers": [], "additional": [], "authorities": [], "questions": []}
    if len(data) < 12:
        return out
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    out["header"] = {
        "id": struct.unpack(">H", data[0:2])[0],
        "is_response": bool(data[2] & 0x80),
        "authoritative": bool(data[2] & 0x04),
    }
    pos = 12
    for _ in range(qd):
        name, pos = _dns_read_name(data, pos)
        if pos + 4 > len(data):
            break
        qtype, _cls = struct.unpack(">HH", data[pos : pos + 4])
        pos += 4
        out["questions"].append({"name": name, "type": _DNS_TYPES.get(qtype, qtype)})

    def _records(count: int, sink: list[dict[str, Any]]) -> None:
        nonlocal pos
        for _ in range(count):
            if pos >= len(data):
                return
            name, pos = _dns_read_name(data, pos)
            if pos + 10 > len(data):
                return
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[pos : pos + 10])
            pos += 10
            rdata = data[pos : pos + rdlength]
            end = pos + rdlength
            rec: dict[str, Any] = {"name": name, "type": _DNS_TYPES.get(rtype, rtype), "ttl": _ttl}
            try:
                if rtype == 1 and rdlength == 4:
                    rec["value"] = str(ipaddress.IPv4Address(rdata))
                elif rtype == 28 and rdlength == 16:
                    rec["value"] = str(ipaddress.IPv6Address(rdata))
                elif rtype in (12, 2, 5):
                    rec["value"], _ = _dns_read_name(data, pos)
                elif rtype == 33 and rdlength >= 7:
                    prio, weight, port = struct.unpack(">HHH", rdata[:6])
                    target, _ = _dns_read_name(data, pos + 6)
                    rec["value"] = {"priority": prio, "weight": weight, "port": port, "target": target}
                elif rtype == 16:
                    txt = rdata
                    i = 0
                    parts = []
                    while i < len(txt):
                        ln = txt[i]
                        parts.append(txt[i + 1 : i + 1 + ln].decode("utf-8", errors="replace"))
                        i += 1 + ln
                    rec["value"] = parts
                    rec["text"] = " ".join(parts)
                elif rtype == 47:  # NSEC (mDNS)
                    rec["value"] = "NSEC"
                else:
                    rec["value"] = rdata.hex()
            except Exception:
                rec["value"] = None
            sink.append(rec)
            pos = end

    _records(an, out["answers"])
    _records(ns, out["authorities"])
    _records(ar, out["additional"])
    return out


# ======================================================================================
# 4) SNMP (BER)
# ======================================================================================
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _ber_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def ber_encode_int(n: int) -> bytes:
    if n == 0:
        raw = b"\x00"
    else:
        raw = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return _ber_tlv(0x02, raw)


def ber_encode_octets(s: bytes) -> bytes:
    return _ber_tlv(0x04, s)


def ber_encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    raw = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        raw += bytes(reversed(chunk))
    return _ber_tlv(0x06, raw)


def ber_encode_null() -> bytes:
    return b"\x05\x00"


def snmp_get_packet(community: str, oids: list[str], request_id: int = 1) -> bytes:
    varbinds = b"".join(
        _ber_tlv(0x30, ber_encode_oid(o) + ber_encode_null()) for o in oids
    )
    pdu = _ber_tlv(0xA0, ber_encode_int(request_id) + ber_encode_int(0) + ber_encode_int(0) + _ber_tlv(0x30, varbinds))
    msg = ber_encode_int(0) + ber_encode_octets(community.encode()) + pdu
    return _ber_tlv(0x30, msg)


def _ber_read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = data[pos]
    ln, pos = _der_read_length(data, pos + 1)
    return tag, data[pos : pos + ln], pos + ln


def _ber_int(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True) if raw else 0


def snmp_parse_response(data: bytes, community: str = "public") -> dict[str, Any]:
    """استخراج جفت‌های OID/مقدار از پاسخ SNMP v1/v2c."""
    out: dict[str, Any] = {"values": {}, "error": None}
    try:
        tag, msg, _ = _ber_read_tlv(data, 0)
        if tag != 0x30:
            raise ValueError("SNMP: قالب نامعتبر")
        p = 0
        _, version_raw, p = _ber_read_tlv(msg, p)
        _, comm_raw, p = _ber_read_tlv(msg, p)
        if comm_raw.decode("latin-1") != community:
            out["error"] = "community mismatch"
        _, pdu, p = _ber_read_tlv(msg, p)
        q = 0
        _, err_raw, q = _ber_read_tlv(pdu, q)
        out["error_status"] = _ber_int(err_raw)
        _, _, q = _ber_read_tlv(pdu, q)
        _, _, q = _ber_read_tlv(pdu, q)
        _, vbl, q = _ber_read_tlv(pdu, q)
        r = 0
        while r < len(vbl):
            _, vb, r = _ber_read_tlv(vbl, r)
            s = 0
            oid_tag, oid_raw, s = _ber_read_tlv(vb, s)
            if oid_tag != 0x06:
                continue
            oid = _ber_oid_str(oid_raw)
            vtag, vraw, s = _ber_read_tlv(vb, s)
            val: Any
            if vtag == 0x04:
                val = vraw.decode("utf-8", errors="replace").strip()
            elif vtag in (0x02, 0x41, 0x42, 0x43, 0x46):
                val = _ber_int(vraw)
            elif vtag == 0x40:  # IpAddress
                val = str(ipaddress.IPv4Address(vraw)) if len(vraw) == 4 else vraw.hex()
            elif vtag == 0x06:
                val = _ber_oid_str(vraw)
            elif vtag == 0x05:
                val = None
            else:
                try:
                    val = vraw.decode("utf-8")
                except Exception:
                    val = vraw.hex()
            if val not in (None, "", b""):
                out["values"][oid] = val
    except Exception as e:                                    # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def _ber_oid_str(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


SNMP_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.7.0": "sysServices",
    "1.3.6.1.2.1.2.2.1.6.1": "ifPhysAddress(1)",
    "1.3.6.1.2.1.2.2.1.2.1": "ifDescr(1)",
    "1.3.6.1.2.1.25.3.2.1.3.1": "hrDeviceDescr(1)",
    "1.3.6.1.4.1.43.5.1.1.16.1": "prtGeneralSerialNumber(1)",
    "1.3.6.1.2.1.43.5.1.1.17.1": "prtGeneralPrinterName(1)",
}


# ======================================================================================
# 5) DHCP leases  (فایل‌های واقعی سرور DHCP روی همین دستگاه یا مسیرهای رایج)
# ======================================================================================
def parse_dhcp_leases(text: str) -> list[dict[str, Any]]:
    """
    تجزیهٔ فایل اجارهٔ dnsmasq، ISC dhcpd و Kea.
    هر رکورد: MAC، IP، نام میزبان، زمان پایان، Client-ID.
    """
    leases: list[dict[str, Any]] = []

    # --- dnsmasq format ---
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(
            r"^(\d+)\s+([0-9a-fA-F:]{17})\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)(?:\s+(\S+))?",
            line,
        )
        if m:
            expiry, mac, ip, name = m.group(1), m.group(2), m.group(3), m.group(4)
            entry = {
                "ip": ip,
                "mac": mac.lower(),
                "expiry": int(expiry),
                "hostname": None if name == "*" else name,
                "client_id": m.group(5),
                "format": "dnsmasq",
            }
            if entry["hostname"]:
                entry["hostname_source"] = "DHCP lease (dnsmasq)"
            leases.append(entry)

    # --- ISC dhcpd format ---
    for block in re.findall(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}", text, re.S):
        ip, body = block
        hw = re.search(r"hardware\s+ethernet\s+([0-9a-fA-F:]{17})", body)
        hn = re.search(r'client-hostname\s+"([^"]+)"', body)
        ci = re.search(r'uid\s+([^;]+);', body)
        ends = re.search(r"ends\s+\d+\s+([\d/]+\s+[\d:]+)", body)
        leases.append(
            {
                "ip": ip,
                "mac": hw.group(1).lower() if hw else None,
                "hostname": hn.group(1) if hn else None,
                "hostname_source": "DHCP lease (ISC dhcpd)" if hn else None,
                "client_id": ci.group(1).strip() if ci else None,
                "expiry_human": ends.group(1) if ends else None,
                "format": "isc-dhcpd",
            }
        )
    return leases


# ======================================================================================
# 6) HTML / banner helpers
# ======================================================================================
_TITLE_RE = re.compile(rb"<title[^>]*>(.{0,200}?)</title>", re.I | re.S)


def extract_html_title(body: bytes) -> str | None:
    m = _TITLE_RE.search(body or b"")
    if not m:
        return None
    raw = re.sub(rb"\s+", b" ", m.group(1)).strip()
    for enc in ("utf-8", "windows-1256", "latin-1"):
        try:
            return raw.decode(enc).strip()
        except Exception:
            continue
    return None


def parse_http_response(head: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"headers": {}, "status": None, "status_text": None}
    text = head.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            try:
                out["status"] = int(parts[1])
            except ValueError:
                out["status"] = parts[1]
        if len(parts) >= 3:
            out["status_text"] = parts[2]
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            k, v = line.split(":", 1)
            out["headers"][k.strip().lower()] = v.strip()
    return out


def parse_html_head_fields(head: bytes) -> dict[str, str]:
    """خواندن متا تگ‌هایی که بعضی دستگاه‌ها (روتر/دوربین) مدل را در آن می‌گذارند."""
    out: dict[str, str] = {}
    text = head.decode("utf-8", errors="replace")
    for name in ("description", "author", "application-name", "generator", "title"):
        m = re.search(rf'<meta[^>]+name=["\']{name}["\'][^>]+content=["\']([^"\']{{1,160}})["\']', text, re.I)
        if m:
            out[name] = m.group(1)
    return out
