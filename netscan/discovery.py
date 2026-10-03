"""
discovery.py — لایه‌های کشف میزبان (Host discovery).

هدف: هیچ دستگاه زنده‌ای از قلم نیفتد و هر یافته **شاهد واقعی** داشته باشد.
هیچ‌جا «حدس» زده نمی‌شود؛ هر روش، شاهد خودش را ثبت می‌کند:

1.  arp_sweep                → شاهد سطح ۲ (MAC واقعی از پاسخ ARP)  [نیاز به دسترسی root]
2.  icmp_echo_sweep          → پاسخ ICMP Echo                     [root]
3.  icmp_timestamp_sweep     → پاسخ ICMP Timestamp (لینوکس/ویندوز/مک پاسخ می‌دهند) [root]
4.  tcp_syn_sweep            → SYN/ACK یا RST از پورت‌های رایج     [root]
5.  tcp_connect_sweep        → اتصال TCP کامل                     [بدون root]
6.  udp_probe_sweep          → پاسخ سرویس UDP یا ICMP port-unreachable (زنده بودن) [بدون root]
7.  ping_command_sweep       → ابزار ping سیستم + جدول ARP        [بدون root]
8.  passive_sources()        → جدول ARP/NDP، اجاره‌های DHCP، اتصال‌های فعال سیستم
"""

from __future__ import annotations

import errno
import glob
import ipaddress
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event as _Event
from typing import Any, Callable, Iterable

from . import netinfo, parsers

Progress = Callable[[str, float], None]


def _noop(_msg: str, _pct: float = 0.0) -> None:
    return None


# ======================================================================================
# Raw-socket helpers
# ======================================================================================
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class RawCapabilities:
    """کدام لایه‌های اسکن در این سیستم قابل استفاده‌اند و چرا نه."""

    def __init__(self) -> None:
        self.arp = False
        self.icmp = False
        self.tcp_syn = False
        self.reasons: dict[str, str] = {}
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not sys.platform.startswith("linux"):
            self.reasons["arp"] = "اسکن ARP خام فقط در لینوکس پشتیبانی می‌شود."
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            s.close()
            self.arp = True
        except Exception as e:                                # noqa: BLE001
            self.reasons["arp"] = f"دسترسی به سوکت خام ARP ممکن نیست ({e})"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            self.icmp = True
        except Exception as e:                                # noqa: BLE001
            self.reasons["icmp"] = f"دسترسی به سوکت خام ICMP ممکن نیست ({e})"
        if sys.platform.startswith("linux"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.close()
                self.tcp_syn = True
            except Exception as e:                            # noqa: BLE001
                self.reasons["tcp_syn"] = f"دسترسی به سوکت خام TCP ممکن نیست ({e})"
        else:
            self.reasons["tcp_syn"] = "اسکن SYN خام در این سیستم‌عامل پشتیبانی نمی‌شود."

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.is_root,
            "arp_raw": self.arp,
            "icmp_raw": self.icmp,
            "tcp_syn_raw": self.tcp_syn,
            "reasons": self.reasons,
        }


# ======================================================================================
# 1) ARP sweep  — قوی‌ترین روش در شبکهٔ محلی (دستگاه خاموش هم ... نه، ولی فایروال‌ها
#    نمی‌توانند ARP را پنهان کنند؛ هر دستگاه IP-دار در LAN باید پاسخ ARP بدهد)
# ======================================================================================
def _iface_mac(iface: str) -> bytes | None:
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip()
        if len(mac.split(":")) == 6:
            return bytes(int(x, 16) for x in mac.split(":"))
    except Exception:
        pass
    return None


def arp_sweep(iface: str, my_ip: str, targets: list[str], timeout: float = 1.2,
              retries: int = 2, cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    """ارسال درخواست ARP به همهٔ آدرس‌ها و ثبت MAC از پاسخ‌های واقعی."""
    result: dict[str, dict[str, Any]] = {}
    mac = _iface_mac(iface)
    if mac is None:
        return result
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except Exception:
        return result
    try:
        s.bind((iface, 0))
        s.setblocking(False)
        src_ip = socket.inet_aton(my_ip)
        for attempt in range(max(1, retries)):
            if cancel is not None and cancel.is_set():
                break
            for ip in targets:
                if ip in result and attempt > 0:
                    continue
                try:
                    tgt = socket.inet_aton(ip)
                except OSError:
                    continue
                eth = b"\xff" * 6 + mac + struct.pack("!H", 0x0806)
                arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + src_ip + b"\x00" * 6 + tgt
                try:
                    s.send(eth + arp)
                except OSError:
                    pass
                time.sleep(0.0006)
            deadline = time.time() + timeout
            while time.time() < deadline:
                r, _, _ = select.select([s], [], [], max(0.0, deadline - time.time()))
                if not r:
                    break
                try:
                    frame = s.recv(2048)
                except OSError:
                    continue
                if len(frame) < 42:
                    continue
                eth_type = struct.unpack("!H", frame[12:14])[0]
                if eth_type not in (0x0806, 0x8035):
                    continue
                payload = frame[14:]
                if len(payload) < 28:
                    continue
                htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", payload[:8])
                if op not in (1, 2) or hlen != 6 or plen != 4:
                    continue
                sender_mac = ":".join(f"{b:02x}" for b in payload[8:14])
                sender_ip = socket.inet_ntoa(payload[14:18])
                if sender_ip in ("0.0.0.0", my_ip):
                    continue
                if sender_mac == "00:00:00:00:00:00":
                    continue
                result.setdefault(sender_ip, {
                    "mac": sender_mac,
                    "method": "arp",
                    "evidence": ("پاسخ ARP دریافتی (شاهد قطعی سطح ۲: MAC از خود دستگاه)"
                                 if op == 2 else
                                 "اعلام ARP بی‌درخواست/Probe از خود دستگاه (شاهد سطح ۲)"),
                })
            if len(result) >= len(targets) * 0.98:
                break
    finally:
        s.close()
    return result


# ======================================================================================
# 2) ICMP echo / timestamp sweep  (سوکت خام)
# ======================================================================================
def icmp_sweep(iface: str, my_ip: str, targets: list[str], kind: str = "echo",
               timeout: float = 1.5, retries: int = 2, batch: int = 512,
               cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    iface_ip = socket.inet_aton(my_ip)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception:
        return result
    try:
        s.setblocking(False)
        ident = random.randint(1, 0x7FFF)
        pending: dict[int, str] = {}
        seq = 0
        sent_at: dict[int, float] = {}
        for attempt in range(max(1, retries)):
            if cancel is not None and cancel.is_set():
                break
            todo = [ip for ip in targets if ip not in result]
            if not todo:
                break
            for ip in todo[:batch * 4]:
                seq = (seq + 1) & 0xFFFF
                ts = int(time.time() * 1000) & 0xFFFFFFFF
                if kind == "timestamp":
                    body = struct.pack("!HHHH", ident, seq, ts, 0)
                    itype = 13
                else:
                    body = struct.pack("!HH", ident, seq) + struct.pack("!d", time.time()) + b"netscan"
                    itype = 8
                hdr = struct.pack("!BBHHH", itype, 0, 0, ident, seq)
                csum = _checksum(hdr + body)
                hdr = struct.pack("!BBHHH", itype, 0, csum, ident, seq)
                try:
                    s.sendto(hdr + body, (ip, 0))
                    pending[seq] = ip
                    sent_at[seq] = time.time()
                except OSError as e:
                    if e.errno == errno.EPERM:
                        return result
                if len(pending) >= batch:
                    _icmp_drain(s, pending, sent_at, result, my_ip, timeout, kind)
                    pending = {k: v for k, v in pending.items() if v not in result}
            _icmp_drain(s, pending, sent_at, result, my_ip, timeout, kind, force_wait=True)
    finally:
        s.close()
    return result


def _icmp_drain(sock: socket.socket, pending: dict[int, str], sent_at: dict[int, float],
                result: dict[str, dict[str, Any]], my_ip: str, timeout: float,
                kind: str, force_wait: bool = False) -> None:
    deadline = time.time() + (timeout if force_wait else 0.35)
    while pending and time.time() < deadline:
        r, _, _ = select.select([sock], [], [], max(0.0, deadline - time.time()))
        if not r:
            break
        try:
            pkt, addr = sock.recvfrom(4096)
        except OSError:
            break
        src = addr[0]
        if src == my_ip:
            continue
        if len(pkt) < 20:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 8:
            continue
        proto = pkt[9]
        if proto not in (1, 58):
            continue
        icmp = pkt[ihl:]
        itype = icmp[0]
        expected = (0, 14) if kind == "timestamp" else (0,)
        if itype in expected and len(icmp) >= 8:
            ident, seq = struct.unpack("!HH", icmp[4:8])
            if seq in pending and pending[seq] == src:
                rtt = (time.time() - sent_at.get(seq, time.time())) * 1000
                result[src] = {
                    "method": f"icmp_{kind}",
                    "rtt_ms": round(rtt, 2),
                    "evidence": (
                        "پاسخ ICMP Timestamp دریافت شد" if kind == "timestamp"
                        else "پاسخ ICMP Echo دریافت شد"
                    ),
                }
                pending.pop(seq, None)
        elif itype == 3 and len(icmp) >= 8 + 20:
            # ICMP unreachable for our probe = host is reachable at L3
            inner = icmp[8:]
            if inner[9] == 1:
                inner_ihl = (inner[0] & 0x0F) * 4
                if len(inner) >= inner_ihl + 8:
                    i_ident, i_seq = struct.unpack("!HH", inner[inner_ihl + 4 : inner_ihl + 8])
                    if i_seq in pending and pending[i_seq] == src and src not in result:
                        result[src] = {
                            "method": f"icmp_{kind}_unreachable",
                            "evidence": "دستگاه با پیام ICMP پاسخ داد (خطای غیرقابل‌دسترس‌بودن = میزبان زنده است)",
                        }
                        pending.pop(i_seq, None)


def tcp_syn_sweep(iface: str, my_ip: str, targets: list[str], ports: list[int],
                  timeout: float = 1.5, cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    """اسکن SYN خام: پاسخ SYN/ACK یا RST یعنی میزبان قطعاً زنده است."""
    result: dict[str, dict[str, Any]] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except Exception:
        return result
    try:
        s.setblocking(False)
        src_ip = socket.inet_aton(my_ip)
        sent: dict[tuple[str, int], float] = {}
        for ip in targets:
            if cancel is not None and cancel.is_set():
                break
            for port in ports:
                sport = random.randint(20000, 60000)
                seqn = random.randint(1, 0xFFFFFFF)
                tcp = struct.pack("!HHIIBBHHH", sport, port, seqn, 0, 5 << 4, 0x02, 64240, 0, 0)
                pseudo = src_ip + socket.inet_aton(ip) + struct.pack("!BBH", 0, 6, len(tcp))
                csum = _checksum(pseudo + tcp)
                tcp = struct.pack("!HHIIBBHHH", sport, port, seqn, 0, 5 << 4, 0x02, 64240, csum, 0)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(1, 65535), 0, 64, 6, 0,
                                     src_ip, socket.inet_aton(ip))
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, struct.unpack("!H", ip_hdr[4:6])[0], 0, 64, 6,
                                     _checksum(ip_hdr), src_ip, socket.inet_aton(ip))
                try:
                    s.sendto(ip_hdr + tcp, (ip, 0))
                except OSError as e:
                    if e.errno == errno.EPERM:
                        return result
                sent[(ip, port)] = time.time()
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([s], [], [], max(0.0, deadline - time.time()))
            if not r:
                break
            try:
                pkt, addr = s.recvfrom(4096)
            except OSError:
                break
            src = addr[0]
            if len(pkt) < 40:
                continue
            ihl = (pkt[0] & 0x0F) * 4
            if len(pkt) < ihl + 20:
                continue
            flags = pkt[ihl + 13]
            is_synack = (flags & 0x12) == 0x12
            is_rst = bool(flags & 0x04)
            if is_synack or is_rst:
                rec = result.setdefault(src, {
                    "method": "tcp_syn", "open_tcp_ports": [], "rtt_ms": None,
                    "evidence": "پاسخ TCP سطح ۳ (SYN/ACK یا RST) دریافت شد — میزبان قطعاً زنده است",
                })
                if is_synack:
                    src_port = struct.unpack("!H", pkt[ihl : ihl + 2])[0]
                    rec["open_tcp_ports"] = sorted(set(rec.get("open_tcp_ports", []) + [src_port]))
                    rec["closed_evidence"] = rec.get("closed_evidence") or "دست‌کم یک پورت پاسخ RST داده است"
                else:
                    rec["closed_evidence"] = "پاسخ RST دریافت شد (پورت بسته، ولی میزبان زنده است)"
                age = min((time.time() - t for t in sent.values()), default=0)
                rec["rtt_ms"] = round(age * 1000, 2)
    finally:
        s.close()
    return result


# ======================================================================================
# 3) TCP connect sweep (بدون دسترسی root)
# ======================================================================================
def tcp_connect_sweep(targets: list[str], ports: list[int], timeout: float = 0.6,
                      workers: int = 256, progress: Progress = _noop,
                      cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    lock = __import__("threading").Lock()
    total = len(targets) * len(ports)
    done = 0

    def _try(args: tuple[str, int]) -> None:
        nonlocal done
        ip, port = args
        if cancel is not None and cancel.is_set():
            return
        s = None
        t0 = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            with lock:
                done += 1
            if rc == 0:
                rtt = (time.time() - t0) * 1000
                with lock:
                    rec = result.setdefault(ip, {"method": "tcp_connect", "open_tcp_ports": [],
                                                 "evidence": "اتصال کامل TCP برقرار شد (شاهد قطعی)"})
                    rec["open_tcp_ports"] = sorted(set(rec.get("open_tcp_ports", []) + [port]))
                    rec["rtt_ms"] = round(rtt, 2)
        except (socket.timeout, OSError):
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        if done % 64 == 0:
            progress(f"اسکن TCP: {done}/{total}", (done / max(1, total)) * 100)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_try, ((ip, p) for ip in targets for p in ports)))
    return result


def udp_probe_sweep(targets: list[str], timeout: float = 0.5, workers: int = 128,
                    payloads: dict[int, bytes] | None = None,
                    cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    """
    کاوش UDP: برای هر میزبان چند پورت UDP امتحان می‌شود.
    - پاسخ دادهٔ واقعی → سرویس شناسایی‌شده + میزبان زنده
    - ICMP port-unreachable (خطای ECONNREFUSED روی سوکت متصل) → میزبان زنده است، پورت بسته
    """
    result: dict[str, dict[str, Any]] = {}
    payloads = payloads or {
        5353: _mdns_query_bytes("_services._dns-sd._udp.local"),
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
        137: _nbns_query_bytes(),
        161: parsers.snmp_get_packet("public", ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]),
        37: b"\x00\x00\x00\x00",
    }
    lock = __import__("threading").Lock()

    def _try(args: tuple[str, int]) -> None:
        ip, port = args
        if cancel is not None and cancel.is_set():
            return
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(payloads.get(port, b"\x00"))
            data, _ = s.recvfrom(65535)
            with lock:
                rec = result.setdefault(ip, {"method": "udp", "udp_replies": [], "evidence": "پاسخ UDP دریافتی"})
                rec["udp_replies"].append({"port": port, "bytes": len(data), "raw": data[:1500].hex()})
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            with lock:
                rec = result.setdefault(ip, {
                    "method": "udp", "udp_replies": [],
                    "evidence": "پاسخ ICMP port-unreachable: میزبان زنده است (پورت UDP بسته)",
                })
                rec.setdefault("closed_udp_ports", []).append(port)
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                with lock:
                    rec = result.setdefault(ip, {
                        "method": "udp", "udp_replies": [],
                        "evidence": "پاسخ ICMP port-unreachable: میزبان زنده است (پورت UDP بسته)",
                    })
                    rec.setdefault("closed_udp_ports", []).append(port)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_try, ((ip, p) for ip in targets for p in payloads)))
    return result


# ======================================================================================
# 4) ping command + ARP table  (بدون root، برای همهٔ سیستم‌ها)
# ======================================================================================
def ping_command_sweep(targets: list[str], workers: int = 128, timeout: float = 1.0,
                       progress: Progress = _noop,
                       cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    lock = __import__("threading").Lock()
    count = [0]
    is_win = sys.platform.startswith("win")

    def _ping(ip: str) -> None:
        if cancel is not None and cancel.is_set():
            return
        cmd = (["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if is_win
               else ["ping", "-c", "1", "-W", str(max(1, int(timeout + 0.5))), ip])
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout + 1.5)
            with lock:
                count[0] += 1
                if count[0] % 50 == 0:
                    progress(f"ping: {count[0]}", 0)
            if p.returncode == 0:
                with lock:
                    result[ip] = {"method": "ping_command",
                                  "evidence": "پاسخ ابزار ping سیستم (ICMP Echo)"}
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_ping, targets))
    return result


def arp_table() -> dict[str, dict[str, Any]]:
    """جدول ARP/NDP هستهٔ سیستم (شاهد واقعی MAC، حتی برای دستگاه‌هایی که ما اسکن نکردیم)."""
    out: dict[str, dict[str, Any]] = {}
    text = ""
    try:
        text = subprocess.run(["ip", "-j", "neigh"], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        text = ""
    if text.strip():
        try:
            import json

            for row in json.loads(text):
                ip = row.get("dst")
                mac = (row.get("lladdr") or "").lower()
                if not ip or not mac:
                    continue
                if ":" in ip:                     # IPv6 neighbour
                    continue
                state = (row.get("state") or [None])[0]
                out[ip] = {
                    "mac": mac,
                    "iface": row.get("dev"),
                    "state": state,
                    "method": "arp_table",
                    "evidence": (f"ورودی جدول ARP هستهٔ سیستم‌عامل با وضعیت {state} — "
                                 "نشان می‌دهد این دستگاه تازه با این سیستم تبادل داشته است (شاهد سطح ۲)"),
                }
        except Exception:
            pass
    if not out:
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        out[parts[0]] = {
                            "mac": parts[3].lower(),
                            "iface": parts[5] if len(parts) > 5 else None,
                            "method": "arp_table",
                            "evidence": "ورودی /proc/net/arp (جدول ARP هسته)",
                        }
        except Exception:
            pass
    if not out and sys.platform.startswith("win"):
        try:
            txt = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8).stdout
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", txt):
                out[m.group(1)] = {
                    "mac": m.group(2).replace("-", ":").lower(),
                    "method": "arp_table",
                    "evidence": "خروجی arp -a (جدول ARP سیستم)",
                }
        except Exception:
            pass
    if not out and sys.platform == "darwin":
        try:
            txt = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=8).stdout
            for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", txt):
                out[m.group(1)] = {
                    "mac": m.group(2).lower(),
                    "method": "arp_table",
                    "evidence": "خروجی arp -an (جدول ARP سیستم)",
                }
        except Exception:
            pass
    return out


def ipv6_neighbours() -> dict[str, dict[str, Any]]:
    """
    جدول همسایگی IPv6 هسته (NDP): با MAC می‌توان آن را به رکورد IPv4 همان دستگاه
    متصل کرد (تطبیق بر اساس MAC واقعی — نه حدس).
    """
    out: dict[str, dict[str, Any]] = {}
    text = ""
    try:
        text = subprocess.run(["ip", "-j", "-6", "neigh"], capture_output=True,
                              text=True, timeout=8).stdout
    except Exception:
        text = ""
    if text.strip():
        try:
            import json as _json

            for row in _json.loads(text):
                mac = (row.get("lladdr") or "").lower()
                dst = row.get("dst")
                if not mac or not dst:
                    continue
                entry = out.setdefault(mac, {"addresses": [], "states": [], "device": row.get("dev"),
                                             "method": "ipv6_neighbour",
                                             "evidence": "ورودی جدول همسایگی IPv6 هسته (NDP) برای همین MAC"})
                entry["addresses"].append(dst.split("%")[0])
                st = (row.get("state") or [None])[0]
                if st:
                    entry["states"].append(st)
        except Exception:
            pass
    return out


# ======================================================================================
# 5) منابع غیرفعال (Passive) — بدون فرستادن حتی یک بسته
# ======================================================================================
DHCP_LEASE_PATHS = [
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dhcp/dnsmasq.leases",
    "/tmp/dnsmasq.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
    "/var/lib/kea/kea-leases4.csv",
    "/etc/kea/kea-leases4.csv",
    "/var/db/dhcpd.leases",
]


def dhcp_leases() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in DHCP_LEASE_PATHS + glob.glob("/var/lib/NetworkManager/*.lease"):
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except Exception:
            continue
        for lease in parsers.parse_dhcp_leases(text):
            ip = lease.get("ip")
            if not ip:
                continue
            entry = out.setdefault(ip, {"method": "dhcp_lease", "evidence": f"پروندهٔ اجارهٔ DHCP: {path}"})
            entry["mac"] = lease.get("mac") or entry.get("mac")
            if lease.get("hostname"):
                entry["dhcp_hostname"] = lease["hostname"]
                entry["dhcp_hostname_source"] = lease.get("hostname_source") or f"فایل اجارهٔ DHCP ({path})"
            entry["lease_path"] = path
    return out


def active_connections() -> dict[str, dict[str, Any]]:
    """آدرس‌های همتا در اتصال‌های فعال این دستگاه (شاهد مستقیم وجود دستگاه دیگر)."""
    out: dict[str, dict[str, Any]] = {}
    try:
        p = subprocess.run(["ss", "-tun"], capture_output=True, text=True, timeout=8)
        if p.returncode != 0:
            p = subprocess.run(["netstat", "-tun"], capture_output=True, text=True, timeout=8)
        for line in p.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            peer = parts[4] if parts[0].lower().startswith(("tcp", "udp")) else None
            if peer is None:
                continue
            ip = peer.rsplit(":", 1)[0].strip("[]%")
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                out.setdefault(ip, {
                    "method": "active_connection",
                    "evidence": "اتصال فعال فعلی سیستم با این آدرس (شاهد مستقیم)",
                })
    except Exception:
        pass
    return out


def listen_sockets_local() -> list[dict[str, Any]]:
    """پورت‌های باز روی خود این دستگاه (برای نمایش «دستگاه من»)."""
    out = []
    try:
        p = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True, timeout=8)
        for line in p.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4]
            ip, _, port = local.rpartition(":")
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
            out.append({"proto": proto, "port": port, "bind": ip or "*", "process": proc})
    except Exception:
        pass
    return out


# ======================================================================================
# mDNS / NBNS packet builders (برای کاوش فعال و خواندن پاسخ‌ها)
# ======================================================================================
def _mdns_query_bytes(name: str, qtype: int = 12, unicast: bool = False) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        if label:
            q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 0x8001 if unicast else 1)
    return header + q


def _nbns_query_bytes(name: str = "*") -> bytes:
    """NBSTAT (NetBIOS node status) query — نام دستگاه و MAC را برمی‌گرداند."""
    if name == "*":
        encoded = b"\x43\x4b" + b"\x00" * 30       # wildcard name
    else:
        pad = (name.upper() + " " * 15)[:15]
        encoded = b""
        for ch in pad.encode():
            encoded += bytes([(ch >> 4) + 0x41, (ch & 0x0F) + 0x41])
    txn = random.randint(1, 0xFFFF)
    header = struct.pack("!HHHHHH", txn, 0x0000, 1, 0, 0, 0)
    question = bytes([32]) + encoded + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)
    return header + question


def mdns_query(addresses: Iterable[str], timeout: float = 2.0, iface_ip: str | None = None,
               cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    """
    کوئری mDNS: نام میزبان (از طریق PTR معکوس) و سرویس‌های اعلام‌شده.
    پاسخ‌ها شاهد قطعی نام/نوع دستگاه هستند.
    """
    out: dict[str, dict[str, Any]] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if iface_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            except OSError:
                pass
        s.bind(("0.0.0.0", 0))
        s.settimeout(timeout)
    except Exception:
        return out
    try:
        addr_list = list(addresses)
        # 1) پرس‌وجوی معکوس برای هر آدرس (نام میزبان دقیق)
        for ip in addr_list:
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            try:
                s.sendto(_mdns_query_bytes(rev, 12), (ip, 5353))
            except OSError:
                pass
        time.sleep(0.15)
        # 2) پرس‌وجوی سرویس‌های موجود
        for name in ("_services._dns-sd._udp.local", "_device-info._tcp.local", "_http._tcp.local"):
            try:
                s.sendto(_mdns_query_bytes(name, 12), ("224.0.0.251", 5353))
            except OSError:
                pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = s.recvfrom(16384)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            pkt = parsers.parse_dns_packet(data)
            rec = out.setdefault(ip, {"method": "mdns", "records": [], "services": [], "names": [],
                                      "evidence": "پاسخ mDNS (شاهد قطعی نام/سرویس دستگاه)"})
            for r in pkt["answers"] + pkt["additional"]:
                rec["records"].append(r)
                if r["type"] == "PTR" and isinstance(r["value"], str):
                    val = r["value"].rstrip(".")
                    if ".in-addr.arpa" in val.lower() and r["name"].endswith(".in-addr.arpa"):
                        rec["names"].append(val)
                        rec["ptr_reverse"] = val
                    elif val.startswith("_"):
                        rec["services"].append(val)
                elif r["type"] == "A" and isinstance(r["value"], str):
                    rec["ipv4"] = r["value"]
                elif r["type"] == "TXT":
                    rec.setdefault("txt", []).extend(r.get("value") or [])
                elif r["type"] == "SRV" and isinstance(r["value"], dict):
                    rec["services"].append(r["name"].rstrip("."))
                    rec["srv"] = r["value"]
            rec["services"] = sorted(set(rec["services"]))
            rec["names"] = sorted(set(rec["names"]))
    finally:
        s.close()
    return out


def ssdp_discover(timeout: float = 2.5, iface_ip: str | None = None,
                  cancel: _Event | None = None) -> list[dict[str, Any]]:
    """کشف SSDP/UPnP — روترها، تلویزیون‌ها، اسپیکرها و ... با مدل دقیق پاسخ می‌دهند."""
    msgs = [
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
    ]
    found: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        if iface_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            except OSError:
                pass
        s.bind(("0.0.0.0", 0))
        s.settimeout(timeout)
    except Exception:
        return []
    try:
        for msg in msgs:
            try:
                s.sendto(msg, ("239.255.255.250", 1900))
            except OSError:
                pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                break
            except OSError:
                break
            text = data.decode("latin-1", errors="replace")
            headers = {}
            for line in text.splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            key = (addr[0], headers.get("usn", headers.get("st", "")))
            if key in found:
                continue
            found[key] = {
                "ip": addr[0],
                "headers": headers,
                "server": headers.get("server"),
                "location": headers.get("location"),
                "st": headers.get("st"),
                "usn": headers.get("usn"),
                "evidence": "پاسخ SSDP/UPnP دریافتی (شاهد قطعی)",
            }
    finally:
        s.close()
    return list(found.values())


def ws_discovery(timeout: float = 3.0, iface_ip: str | None = None,
                 cancel: _Event | None = None) -> list[dict[str, Any]]:
    """
    WS-Discovery (پورت ۳۷۰۲): دوربین‌های ONVIF، چاپگرها، ویندوز و دستگاه‌های IoT
    با «Scopes» جواب می‌دهند که مدل و سازندهٔ دقیق را داخلش دارند.
    """
    import uuid as _uuid
    import xml.etree.ElementTree as _ET

    mid = f"urn:uuid:{_uuid.uuid4()}"
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        f"<e:Header><w:MessageID>{mid}</w:MessageID>"
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        "</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>"
    )
    body2 = body.replace("<d:Types>dn:NetworkVideoTransmitter</d:Types>", "<d:Types></d:Types>")
    out: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        if iface_ip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            except OSError:
                pass
        s.bind(("0.0.0.0", 0))
        s.settimeout(timeout)
    except Exception:
        return []
    try:
        for payload in (body, body2):
            try:
                s.sendto(payload.encode(), ("239.255.255.250", 3702))
            except OSError:
                pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                break
            try:
                data, addr = s.recvfrom(65535)
            except (socket.timeout, OSError):
                break
            try:
                root = _ET.fromstring(data.decode("utf-8", errors="replace"))
            except Exception:
                continue
            rec: dict[str, Any] = {
                "ip": addr[0],
                "scopes": [],
                "types": None,
                "xaddrs": None,
                "endpoint": None,
                "method": "ws_discovery",
                "evidence": "پاسخ WS-Discovery (شاهد قطعی: خود دستگاه نوع و مدل را اعلام کرده)",
            }
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                txt = (el.text or "").strip()
                if tag == "Address" and txt.startswith("urn:uuid:") and not rec["endpoint"]:
                    rec["endpoint"] = txt
                elif tag == "Types":
                    rec["types"] = txt
                elif tag == "Scopes":
                    rec["scopes"] = [x for x in txt.split() if x]
                elif tag == "XAddrs":
                    rec["xaddrs"] = txt
            key = (rec["ip"], rec.get("endpoint") or "")
            out.setdefault(key, rec)
    finally:
        s.close()
    return list(out.values())


def parse_onvif_scopes(scopes: Iterable[str]) -> dict[str, str]:
    """از Scopes پاسخ ONVIF، فیلدهای هویتی را بیرون می‌کشد (name/hardware/location)."""
    out: dict[str, str] = {}
    for sc in scopes:
        if not sc.startswith("onvif://www.onvif.org/"):
            continue
        parts = sc.split("/")
        if len(parts) >= 6:
            key = parts[4]
            value = "/".join(parts[5:])
            out[key] = value.replace("%20", " ")
    return out


def nbns_query(addresses: Iterable[str], timeout: float = 1.2, workers: int = 64,
               cancel: _Event | None = None) -> dict[str, dict[str, Any]]:
    """NetBIOS Node Status — نام NetBIOS، نام گروه کاری و MAC را از خود دستگاه می‌خواند."""
    out: dict[str, dict[str, Any]] = {}
    lock = __import__("threading").Lock()

    def _ask(ip: str) -> None:
        if cancel is not None and cancel.is_set():
            return
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(_nbns_query_bytes(), (ip, 137))
            data, _ = s.recvfrom(4096)
            if len(data) < 12:
                return
            ancount = struct.unpack("!H", data[6:8])[0]
            if ancount < 1:
                return
            pos = 12
            # skip question
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1 + 4
            while pos < len(data) and data[pos] != 0xC0:
                pos += 1 + data[pos]
            if pos + 2 > len(data):
                return
            pos += 2
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
            pos += 10
            rdata = data[pos : pos + rdlen]
            if rtype != 0x0021 or len(rdata) < 1:
                return
            num = rdata[0]
            names = []
            workgroup = None
            for i in range(num):
                off = 1 + i * 18
                if off + 18 > len(rdata):
                    break
                raw = rdata[off : off + 15]
                name = raw.decode("latin-1").strip()
                suffix = rdata[off + 15]
                flags = struct.unpack("!H", rdata[off + 16 : off + 18])[0]
                is_group = bool(flags & 0x8000)
                if suffix == 0x00:
                    if is_group:
                        workgroup = name
                    else:
                        names.append(name)
                elif suffix == 0x20:
                    names.append(name)
                elif suffix == 0x03:
                    names.append(name)
            mac = None
            if len(rdata) >= 1 + num * 18 + 6:
                mac = ":".join(f"{b:02x}" for b in rdata[1 + num * 18 : 1 + num * 18 + 6])
            with lock:
                out[ip] = {
                    "method": "nbns",
                    "netbios_names": names,
                    "workgroup": workgroup,
                    "mac": mac,
                    "evidence": "پاسخ NetBIOS Node Status (شاهد قطعی نام دستگاه)",
                }
        except (socket.timeout, OSError):
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_ask, addresses))
    return out


def reverse_dns(addresses: Iterable[str], timeout: float = 1.2, workers: int = 48,
                cancel: _Event | None = None) -> dict[str, str]:
    """نام میزبان از DNS معکوس (سرور DNS شبکه). اگر پاسخ ندهد، خالی می‌ماند (بدون حدس)."""
    out: dict[str, str] = {}
    lock = __import__("threading").Lock()
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    def _ptr(ip: str) -> None:
        if cancel is not None and cancel.is_set():
            return
        try:
            name = socket.gethostbyaddr(ip)[0]
            with lock:
                out[ip] = name
        except Exception:
            pass

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(_ptr, list(addresses)))
    finally:
        socket.setdefaulttimeout(old)
    return out


def resolve_hostname(name: str, timeout: float = 2.0) -> list[str]:
    """تبدیل نام به آدرس (برای اسکن هدف واردشده با نام)."""
    try:
        socket.setdefaulttimeout(timeout)
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
    except Exception:
        return []
