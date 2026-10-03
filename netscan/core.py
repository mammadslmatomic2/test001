"""
core.py — موتور اصلی اسکن.

جریان کار:
  ۱. تشخیص رابط شبکه و گسترهٔ آدرس‌ها (دقیق، از هستهٔ سیستم)
  ۲. گردآوری غیرفعال (جدول ARP، اجاره‌های DHCP، اتصال‌های فعال) — بدون ارسال بسته
  ۳. کشف فعال چندلایه (ARP خام، ICMP، TCP SYN، TCP Connect، UDP، ping)
  ۴. ادغام شواهد و ساخت فهرست دستگاه‌ها (هر یافته با «منبع» و «سطح اطمینان»)
  ۵. کاوش عمیق روی هر دستگاه: همهٔ پورت‌ها + شناسایی سرویس + بنر + گواهی TLS + SNMP + IPP
  ۶. کشف چندپخشی: SSDP/UPnP، WS-Discovery/ONVIF، mDNS، NetBIOS
  ۷. تکمیل اطلاعات: سازندهٔ OUI، نام میزبان معکوس، فایل توصیف UPnP
"""

from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from . import discovery, netinfo, probe
from .oui import OuiDatabase

# --------------------------------------------------------------------------------------
# فهرست پورت‌ها
# --------------------------------------------------------------------------------------
QUICK_PORTS = [80, 443, 22, 445, 3389, 8080, 62078, 554, 9100, 139]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 82, 88, 110, 111, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 548, 554, 587, 623, 631, 636, 873,
    902, 993, 995, 1025, 1080, 1433, 1521, 1701, 1723, 1883, 1900, 2000, 2049, 2082, 2083,
    2323, 3000, 3128, 3260, 3306, 3389, 3478, 4000, 4443, 4500, 5000, 5001, 5060, 5061, 5222,
    5269, 5357, 5432, 5500, 5555, 5601, 5683, 5900, 5985, 5986, 6000, 6379, 6443, 7000, 7001,
    7443, 7547, 7681, 8000, 8008, 8009, 8010, 8080, 8081, 8088, 8090, 8123, 8161, 8180, 8443,
    8500, 8530, 8554, 8880, 8883, 8888, 8899, 9000, 9001, 9020, 9050, 9090, 9100, 9200, 9418,
    9443, 9999, 10000, 10250, 11211, 15672, 25565, 27017, 32400, 32469, 37777, 49152, 49153,
    50000, 55554, 62078,
]

TCP_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "rpcbind", 135: "MS RPC", 137: "NetBIOS-NS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB (اشتراک فایل ویندوز)",
    465: "SMTPS", 515: "LPD (چاپ)", 548: "AFP (اشتراک فایل اپل)", 554: "RTSP (استریم/دوربین)",
    587: "SMTP Submission", 623: "IPMI (مدیریت سرور)", 631: "IPP (چاپ اینترنتی)",
    636: "LDAPS", 873: "rsync", 902: "VMware ESXi", 993: "IMAPS", 995: "POP3S",
    1433: "Microsoft SQL Server", 1723: "PPTP VPN", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2323: "Telnet (جایگزین)", 3000: "HTTP (داشبورد)", 3128: "پروکسی Squid",
    3306: "MySQL/MariaDB", 3389: "RDP (ریموت دسکتاپ ویندوز)", 3478: "STUN/TURN", 4000: "HTTP/دستگاه",
    5060: "SIP (VoIP)", 5061: "SIP over TLS", 5222: "XMPP", 5357: "WSDAPI (Web Services)",
    5432: "PostgreSQL", 5555: "ADB / HTTP", 5601: "Kibana", 5683: "CoAP", 5900: "VNC",
    5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 6000: "X11", 6379: "Redis",
    7547: "TR-069 (مدیریت مودم)", 8000: "HTTP (داشبورد)", 8008: "Google Cast (Chromecast)",
    8080: "HTTP (پروکسی/داشبورد)", 8081: "HTTP (دوربین/داشبورد)", 8123: "Home Assistant",
    8443: "HTTPS (داشبورد)", 8500: "Consul", 8554: "RTSP (جایگزین)", 8883: "MQTT over TLS",
    8888: "HTTP (دوربین/داشبورد)", 9000: "HTTP (دوربین/داشبورد)", 9100: "RAW Print (چاپ خام)",
    9200: "Elasticsearch", 9418: "Git", 9999: "HTTP (دوربین/DVR)", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 32400: "Plex Media Server",
    37777: "Dahua DVR (دوربین)", 50000: "SAP / دوربین", 62078: "iPhone/iPad Sync (lockdownd)",
}

UDP_SERVICE_NAMES = {
    53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 69: "TFTP", 123: "NTP",
    137: "NetBIOS Name Service", 138: "NetBIOS Datagram", 161: "SNMP", 1900: "SSDP/UPnP",
    3702: "WS-Discovery", 5353: "mDNS (Bonjour)", 5355: "LLMNR", 5683: "CoAP", 631: "IPP",
}

# پورت‌هایی که معمولاً سرویس وب (بدون TLS) روی آن‌ها اجرا می‌شود
HTTP_PORTS = [80, 81, 82, 88, 3000, 5000, 8000, 8008, 8080, 8081, 8082, 8083, 8088, 8089,
              8090, 8123, 8500, 8888, 9000, 9001, 9999, 10000]
# پورت‌هایی که معمولاً TLS دارند (ابتدا TLS، سپس در صورت شکست HTTP ساده)
HTTPS_PORTS = [443, 4443, 5001, 8443, 9443]
RTSP_PORTS = [554, 8554, 10554, 1554]
BANNER_PORTS = [21, 22, 23, 25, 110, 143, 587, 993, 995, 2222, 22222, 8022]
# روش‌هایی که «زنده‌بودن همین حالا» را ثابت می‌کنند
ACTIVE_METHODS = {
    "arp", "arp_table", "active_connection", "icmp_echo", "icmp_timestamp",
    "icmp_echo_unreachable", "icmp_timestamp_unreachable", "tcp_syn", "tcp_connect",
    "udp", "ping_command", "ssdp", "ws_discovery", "mdns", "nbns", "snmp",
}


def parse_port_list(spec: Any) -> list[int]:
    """
    تجزیهٔ فهرست پورت‌های ورودی کاربر: «8080,8443,9000-9010» → [8080, 8443, 9000, ...]
    """
    ports: list[int] = []
    if not spec:
        return ports
    if isinstance(spec, (list, tuple, set)):
        for item in spec:
            ports.extend(parse_port_list(item))
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    for part in str(spec).replace("،", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if 1 <= lo <= hi <= 65535 and (hi - lo) < 20000:
                ports.extend(range(lo, hi + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.append(port)
    return sorted(set(ports))


# ======================================================================================
class ScanEngine:
    def __init__(self, options: dict[str, Any],
                 emit: Callable[[dict[str, Any]], None] | None = None,
                 cancel: threading.Event | None = None) -> None:
        self.opt = options or {}
        self.emit = emit or (lambda _e: None)
        self.cancel = cancel or threading.Event()
        self.oui = OuiDatabase(extra_paths=self.opt.get("oui_paths"))
        self.warnings: list[str] = []
        self.devices: dict[str, dict[str, Any]] = {}
        self.started = time.time()
        self.caps = discovery.RawCapabilities()
        self.hosts_set: set[str] = set()
        self.stats = {
            "hosts_tested": 0, "devices_found": 0, "open_tcp_ports": 0, "open_udp_ports": 0,
            "probes_blocked": 0, "name_resolutions": 0,
        }

    # ----------------------------------------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        self.emit({"type": "log", "level": level, "message": message})

    def phase(self, name: str, message: str, pct: float) -> None:
        self.emit({"type": "phase", "phase": name, "message": message, "pct": round(pct, 1)})

    # ----------------------------------------------------------------------------------
    def _pick_interface(self) -> tuple[dict[str, Any] | None, str | None]:
        ifaces = netinfo.list_interfaces()
        gw = netinfo.get_gateway() or {}
        wanted = self.opt.get("interface")
        chosen = None
        if wanted:
            for i in ifaces:
                if i["name"] == wanted:
                    chosen = i
                    break
        if chosen is None and gw.get("device"):
            for i in ifaces:
                if i["name"] == gw["device"] and i.get("ipv4"):
                    chosen = i
                    break
        if chosen is None:
            for i in ifaces:
                if not i.get("is_loopback") and i.get("ipv4") and i.get("is_up", True):
                    chosen = i
                    break
        return chosen, gw.get("gateway")

    # ----------------------------------------------------------------------------------
    def run(self) -> dict[str, Any]:
        opt = self.opt
        self.phase("init", "در حال شناسایی رابط شبکه و گسترهٔ آدرس‌ها…", 1)
        iface, gateway = self._pick_interface()
        if iface is None:
            raise RuntimeError("هیچ رابط شبکهٔ IPv4 فعالی پیدا نشد.")
        local_ips = [a["address"] for a in iface.get("ipv4", [])]
        local_ip = local_ips[0] if local_ips else None
        chosen = iface.get("ipv4", [None])[0] or {}

        target = (opt.get("target") or "").strip()
        if target.lower() in ("all", "*", "auto-all", "همه"):
            # همهٔ شبکه‌های IPv4 این دستگاه (به‌جز loopback)
            cidrs = sorted({a["cidr"] for i in netinfo.list_interfaces()
                            if not i.get("is_loopback") for a in i.get("ipv4", [])})
            target = ",".join(cidrs)
            self.log(f"گسترهٔ «همهٔ رابط‌ها» انتخاب شد: {target}")
        if not target:
            target = chosen.get("cidr") or ""
        target_name = target
        if target and "/" not in target and "-" not in target and not all(
                ch.isdigit() or ch == "." for ch in target):
            resolved = discovery.resolve_hostname(target)
            if resolved:
                target = ",".join(resolved)
            else:
                raise RuntimeError(f"نام «{target}» قابل تبدیل به آدرس نبود.")

        try:
            hosts, warn = netinfo.hosts_in(target, max_hosts=int(opt.get("max_hosts", 4096)))
        except ValueError as e:
            raise RuntimeError(str(e)) from e
        if warn:
            self.warnings.append(warn)
        if not hosts:
            raise RuntimeError("فهرست آدرس‌های هدف خالی است.")
        self.stats["hosts_tested"] = len(hosts)

        scope = self._load_private_ranges()
        in_scope = [ip for ip in hosts if self._is_private(ip)]
        if len(in_scope) != len(hosts):
            self.warnings.append(
                f"{len(hosts) - len(in_scope)} آدرس خارج از محدودهٔ خصوصی است. "
                "برای رعایت امنیت، کاوش‌های سطح پایین فقط روی آدرس‌های خصوصی انجام می‌شود."
            )
            hosts = in_scope or hosts

        self.emit({
            "type": "context",
            "context": {
                "interface": iface,
                "interfaces": netinfo.list_interfaces(),
                "local_ip": local_ip,
                "local_ips": local_ips,
                "gateway": gateway,
                "target": target_name,
                "target_expanded": target,
                "host_count": len(hosts),
                "capabilities": self.caps.as_dict(),
                "oui": {"entries": self.oui.size, "sources": self.oui.sources,
                        "fallback_only": self.oui.is_fallback_only},
                "private_ranges": scope,
                "scan_started": self.started,
            },
        })

        if not self.caps.arp and not self.caps.icmp:
            self.warnings.append(
                "دسترسی root در دسترس نیست؛ بنابراین اسکن ARP/ICMP خام انجام نشد. "
                "برای کامل‌ترین نتیجه، برنامه را با دسترسی مدیر (root) اجرا کنید. "
                "در این حالت از TCP/UDP/ping برای کشف استفاده می‌شود."
            )

        # -------------------------- فاز ۱: گردآوری غیرفعال --------------------------
        self.phase("passive", "فاز ۱/۶ — خواندن منابع غیرفعال سیستم (ARP، DHCP، اتصال‌ها)…", 4)
        passive_arp = discovery.arp_table()
        leases = discovery.dhcp_leases()
        conns = discovery.active_connections()
        v6neigh = discovery.ipv6_neighbours()
        for ip, rec in passive_arp.items():
            if self._in_hosts(ip, hosts):
                self._merge(ip, rec)
        for ip, rec in leases.items():
            if self._in_hosts(ip, hosts):
                self._merge(ip, rec)
        for ip, rec in conns.items():
            if self._in_hosts(ip, hosts):
                self._merge(ip, rec)
        # پیوند IPv6 ↔ IPv4 فقط از طریق MAC یکسان (تطبیق واقعی، بدون حدس)
        unmatched_v6 = set(v6neigh) - {d.get("mac") for d in self.devices.values() if d.get("mac")}
        for dev in self.devices.values():
            mac = dev.get("mac")
            if mac and mac in v6neigh:
                dev["ipv6_neighbour"] = v6neigh[mac]
        self.unmatched_ipv6 = len(unmatched_v6)
        if unmatched_v6:
            self.warnings.append(
                f"{len(unmatched_v6)} دستگاه با IPv6 در جدول همسایگی هسته دیده شد که آدرس IPv4 "
                "متناظری برایشان ثبت نشده است (ممکن است واقعاً IPv6-only باشند)."
            )

        # -------------------------- فاز ۲: کشف فعال --------------------------
        mode = (opt.get("mode") or "auto").lower()
        do_full = mode in ("full", "deep", "auto")
        self.phase("discovery", "فاز ۲/۶ — کشف فعال میزبان‌ها…", 10)

        if self.caps.arp and do_full:
            self.log("اجرای اسکن ARP (قوی‌ترین روش در شبکهٔ محلی)…")
            res = discovery.arp_sweep(iface["name"], local_ip, hosts, cancel=self.cancel)
            for ip, rec in res.items():
                self._merge(ip, rec)
            self.log(f"ARP: {len(res)} پاسخ.")

        if self.cancel.is_set():
            return self._finish(hosts, iface, local_ip, gateway, target_name, cancelled=True)

        if self.caps.icmp:
            self.log("اجرای اسکن ICMP Echo…")
            res = discovery.icmp_sweep(iface["name"], local_ip, hosts, "echo", cancel=self.cancel)
            for ip, rec in res.items():
                self._merge(ip, rec)
            self.log(f"ICMP Echo: {len(res)} پاسخ.")
            if do_full:
                self.log("اجرای اسکن ICMP Timestamp (پنجره‌ها/لینوکس/مک به آن پاسخ می‌دهند)…")
                res = discovery.icmp_sweep(iface["name"], local_ip, hosts, "timestamp", cancel=self.cancel)
                for ip, rec in res.items():
                    self._merge(ip, rec)
                self.log(f"ICMP Timestamp: {len(res)} پاسخ.")

        if self.cancel.is_set():
            return self._finish(hosts, iface, local_ip, gateway, target_name, cancelled=True)

        if self.caps.tcp_syn and do_full:
            self.log("اجرای اسکن SYN روی پورت‌های رایج…")
            res = discovery.tcp_syn_sweep(iface["name"], local_ip, hosts, QUICK_PORTS, cancel=self.cancel)
            for ip, rec in res.items():
                self._merge(ip, rec)
            self.log(f"TPC SYN: {len(res)} دستگاه پاسخ داد.")

        self.phase("discovery", "فاز ۲/۶ — اسکن اتصال TCP و کاوش UDP…", 22)
        self.log("اجرای اسکن TCP Connect (بدون نیاز به root)…")
        res = discovery.tcp_connect_sweep(
            hosts, QUICK_PORTS, timeout=float(opt.get("tcp_timeout", 0.7)),
            workers=int(opt.get("workers", 256)),
            progress=lambda m, p: self.phase("discovery", m, 10 + p * 0.12),
            cancel=self.cancel,
        )
        for ip, rec in res.items():
            self._merge(ip, rec)

        self.log("اجرای کاوش UDP (mDNS/SSDP/NBNS/SNMP/port-unreachable)…")
        res = discovery.udp_probe_sweep(hosts, timeout=float(opt.get("udp_timeout", 0.5)),
                                        workers=int(opt.get("workers", 256)), cancel=self.cancel)
        for ip, rec in res.items():
            self._merge(ip, rec)

        known = {ip for ip in self.devices if self.devices[ip].get("alive")}
        if len(known) < len(hosts) and (not self.caps.arp and not self.caps.icmp):
            self.log("اجرای ping سیستمی به‌عنوان لایهٔ پشتیبان…")
            res = discovery.ping_command_sweep([h for h in hosts if h not in known],
                                               workers=min(128, int(opt.get("workers", 256))),
                                               timeout=float(opt.get("ping_timeout", 1.0)),
                                               progress=lambda m, p: self.phase("discovery", m, 30),
                                               cancel=self.cancel)
            for ip, rec in res.items():
                self._merge(ip, rec)
            # پس از ping، جدول ARP دوباره خوانده می‌شود تا MAC دستگاه‌های زنده به‌دست آید
            for ip, rec in discovery.arp_table().items():
                if self._in_hosts(ip, hosts):
                    self._merge(ip, rec)

        alive = sorted([ip for ip in self.devices if self.devices[ip].get("alive")],
                       key=lambda x: tuple(int(p) for p in x.split(".")))
        self.stats["devices_found"] = len(alive)
        self.phase("enrich", f"فاز ۳/۶ — {len(alive)} دستگاه زنده پیدا شد؛ کاوش عمیق…", 34)
        if not alive:
            self.warnings.append(
                "هیچ میزبان زنده‌ای پیدا نشد. اگر مطمئن هستید دستگاه‌ها روشن‌اند: برنامه را با "
                "دسترسی root اجرا کنید، گسترهٔ آدرس را بازبینی کنید، یا مدت انتظار را افزایش دهید."
            )

        # -------------------------- فاز ۳: کاوش عمیق --------------------------
        hosts_list = [h for h in alive if self._is_self(h, local_ips) is False]
        self_hosts = [h for h in alive if self._is_self(h, local_ips)]
        workers = max(4, min(int(opt.get("host_workers", 16)), len(hosts_list) or 1))
        done = 0
        ex = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {ex.submit(self._deep_scan_host, ip, hosts, local_ip, gateway): ip
                       for ip in hosts_list}
            for fut in as_completed(futures):
                done += 1
                ip = futures[fut]
                try:
                    fut.result()
                except Exception as e:                     # noqa: BLE001
                    self.log(f"خطا در کاوش میزبان {ip}: {e}", "warn")
                self.phase("enrich", f"فاز ۳/۶ — کاوش عمیق {done}/{len(hosts_list)} ({ip})",
                           34 + (done / max(1, len(hosts_list))) * 34)
                self.emit({"type": "device_update", "device": self._build_device(ip, gateway, local_ips)})
                if self.cancel.is_set():
                    break
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        if self.cancel.is_set():
            return self._finish(hosts, iface, local_ip, gateway, target_name, cancelled=True)

        # -------------------------- فاز ۴: کشف چندپخشی --------------------------
        if self.cancel.is_set():
            return self._finish(hosts, iface, local_ip, gateway, target_name, cancelled=True)
        self.phase("multicast", "فاز ۴/۶ — کشف SSDP/UPnP و WS-Discovery/ONVIF…", 70)
        try:
            ssdp_entries = discovery.ssdp_discover(timeout=float(opt.get("ssdp_timeout", 2.5)),
                                                   iface_ip=local_ip, cancel=self.cancel)
        except Exception:
            ssdp_entries = []
        for entry in ssdp_entries:
            ip = entry.get("ip")
            if not ip:
                continue
            if not self.devices.get(ip, {}).get("alive"):
                if not self._in_hosts(ip, hosts):
                    continue
                self._merge(ip, {
                    "method": "ssdp",
                    "evidence": "پاسخ SSDP (Multicast) — دستگاه زنده است",
                })
            self.devices[ip].setdefault("ssdp", []).append(entry)
            loc = entry.get("location")
            if loc:
                self._fetch_upnp(loc, hosts, ip)
        if ssdp_entries:
            self.log(f"SSDP: {len(ssdp_entries)} پاسخ.")

        try:
            ws_entries = discovery.ws_discovery(timeout=float(opt.get("ws_timeout", 2.5)),
                                                iface_ip=local_ip, cancel=self.cancel)
        except Exception:
            ws_entries = []
        for entry in ws_entries:
            ip = entry.get("ip")
            if not ip:
                continue
            if not self.devices.get(ip, {}).get("alive") and not self._in_hosts(ip, hosts):
                continue
            if not self.devices.get(ip, {}).get("alive"):
                self._merge(ip, {"method": "ws_discovery",
                                 "evidence": "پاسخ WS-Discovery (Multicast)"})
            if entry.get("scopes"):
                entry["onvif"] = discovery.parse_onvif_scopes(entry["scopes"])
            self.devices[ip].setdefault("ws_discovery", []).append(entry)
        if ws_entries:
            self.log(f"WS-Discovery: {len(ws_entries)} پاسخ.")

        # -------------------------- فاز ۵: نام‌ها و سازنده --------------------------
        if self.cancel.is_set():
            return self._finish(hosts, iface, local_ip, gateway, target_name, cancelled=True)
        self.phase("names", "فاز ۵/۶ — نام میزبان، مDNS، NetBIOS و سازندهٔ OUI…", 78)
        alive_now = [ip for ip in self.devices if self.devices[ip].get("alive")]
        if alive_now:
            self.log("اجرای پرس‌وجوی معکوس DNS…")
            for ip, name in discovery.reverse_dns(alive_now, cancel=self.cancel,
                                                  timeout=float(opt.get("dns_timeout", 1.2))).items():
                dev = self.devices.get(ip)
                if dev is not None:
                    dev["reverse_dns"] = name
                    self.stats["name_resolutions"] += 1
            self.log("اجرای پرس‌وجوی mDNS…")
            for ip, rec in discovery.mdns_query(alive_now,
                                                timeout=float(opt.get("mdns_timeout", 2.0)),
                                                iface_ip=local_ip, cancel=self.cancel).items():
                dev = self.devices.get(ip)
                if dev is not None:
                    dev.setdefault("mdns", []).append(rec)
            self.log("اجرای پرس‌وجوی NetBIOS…")
            for ip, rec in discovery.nbns_query(alive_now, cancel=self.cancel,
                                                timeout=float(opt.get("nbns_timeout", 1.2))).items():
                dev = self.devices.get(ip)
                if dev is not None:
                    dev["netbios"] = rec

        # -------------------------- فاز ۶: ساخت خروجی --------------------------
        self.phase("finalize", "فاز ۶/۶ — ساخت گزارش نهایی…", 92)
        for ip in list(self.devices.keys()):
            if self._is_self(ip, local_ips):
                self._self_facts(ip, local_ip)
        return self._finish(hosts, iface, local_ip, gateway, target_name)

    # ----------------------------------------------------------------------------------
    # کاوش عمیق یک میزبان
    # ----------------------------------------------------------------------------------
    def _deep_scan_host(self, ip: str, hosts: list[str], local_ip: str | None,
                        gateway: str | None) -> None:
        dev = self.devices[ip]
        opt = self.opt
        # ۱) اسکن پورت
        mode = (opt.get("ports") or "common").lower()
        if mode == "all":
            ports = list(range(1, 65536))
        elif mode == "full":
            ports = COMMON_PORTS + list(range(1, 1024)) + list(range(1024, 10000))
            ports = sorted(set(ports))
        elif mode == "quick":
            ports = QUICK_PORTS
        else:
            ports = COMMON_PORTS
        extra = parse_port_list(opt.get("extra_ports"))
        if extra:
            ports = sorted(set(ports) | set(extra))
        if self.cancel.is_set():
            return
        timeout = float(opt.get("tcp_timeout", 0.7))
        if mode == "all":
            timeout = min(timeout, 0.35)
        open_ports = self._scan_ports(ip, ports, timeout, int(opt.get("port_workers", 512)))
        dev["open_tcp_ports"] = open_ports
        self.stats["open_tcp_ports"] += len(open_ports)
        if self.cancel.is_set():
            return

        # ۲) کاوش سرویس‌ها
        services: list[dict[str, Any]] = []
        hostname_hint = dev.get("reverse_dns") or dev.get("dhcp_hostname")
        hh = hostname_hint or None
        # پورت‌هایی که ماهیت غیرِوب دارند و نباید کاوش HTTP روی آن‌ها انجام شود
        non_web = {21, 22, 23, 25, 110, 143, 445, 515, 554, 587, 993, 995, 2049, 3306,
                   3389, 5060, 5432, 5900, 5985, 5986, 62078, 6379, 8554, 9100, 111, 135,
                   1723, 3478, 5061, 5222, 5357, 8883, 1883, 9418, 27017, 10250, 902}
        generic_budget = 24            # حداکثر چند پورت ناشناس برای کاوش عمومی وب

        for p in open_ports:
            if self.cancel.is_set():
                break
            port = p["port"]
            svc: dict[str, Any] = {"port": port, "proto": "tcp",
                                   "service": TCP_SERVICE_NAMES.get(port, p.get("service")),
                                   "evidence": p.get("source")}
            entry: dict[str, Any] | None = None

            if port in HTTPS_PORTS:
                cert = probe.tls_certificate(ip, port, timeout=3.0, server_name=hostname_hint)
                if cert:
                    dev.setdefault("tls", []).append({**cert, "port": port})
                entry = probe.http_probe(ip, port, timeout=max(2.0, timeout), use_tls=True,
                                         host_header=hh)
                if entry is None:
                    entry = probe.http_probe(ip, port, timeout=max(2.0, timeout), use_tls=False,
                                             host_header=hh)
            elif port in HTTP_PORTS:
                entry = probe.http_probe(ip, port, timeout=max(2.0, timeout), use_tls=False,
                                         host_header=hh)
                if entry is None:
                    cert = probe.tls_certificate(ip, port, timeout=3.0, server_name=hostname_hint)
                    if cert:
                        dev.setdefault("tls", []).append({**cert, "port": port})
                        entry = probe.http_probe(ip, port, timeout=max(2.0, timeout), use_tls=True,
                                                 host_header=hh)

            if port in RTSP_PORTS:
                rtsp = probe.rtsp_probe(ip, port)
                if rtsp:
                    dev.setdefault("rtsp", []).append(rtsp)
                    svc["service"] = svc.get("service") or "RTSP (دوربین/استریم)"
                    svc["rtsp"] = rtsp
            if port in (631, 6310):
                ipp = probe.ipp_probe(ip, port)
                if ipp:
                    dev["ipp"] = ipp
                    svc["ipp"] = ipp
            if port in (9100, 515):
                dev["printer_ports"] = sorted(set(dev.get("printer_ports", []) + [port]))
            if port in BANNER_PORTS:
                banner = probe.tcp_banner(ip, port, timeout=2.0)
                if banner:
                    dev.setdefault("banners", []).append(banner)
                    svc["banner"] = banner.get("banner")
                    if banner.get("protocol") == "SSH":
                        dev["ssh"] = banner

            # پورت ناشناخته: کاوش عمومی وب (شاهد واقعی؛ در صورت نبود پاسخ چیزی ثبت نمی‌شود)
            if entry is None and port not in non_web and port not in HTTP_PORTS \
                    and port not in HTTPS_PORTS and generic_budget > 0:
                generic_budget -= 1
                entry = probe.http_probe(ip, port, timeout=1.6, use_tls=False, host_header=hh)
                if entry is None:
                    cert = probe.tls_certificate(ip, port, timeout=2.0, server_name=hostname_hint)
                    if cert:
                        dev.setdefault("tls", []).append({**cert, "port": port})
                        entry = probe.http_probe(ip, port, timeout=1.6, use_tls=True, host_header=hh)
                if entry is None:
                    banner = probe.tcp_banner(ip, port, timeout=1.2)
                    if banner and banner.get("banner"):
                        dev.setdefault("banners", []).append(banner)
                        svc["banner"] = banner["banner"]
                        if banner.get("protocol") == "SSH":
                            dev["ssh"] = banner

            if entry:
                dev.setdefault("http", []).append(entry)
                svc["http"] = {k: entry.get(k) for k in ("scheme", "status", "server", "title")}
                if not svc.get("service"):
                    svc["service"] = "HTTP" if entry.get("scheme") == "http" else "HTTPS"
            services.append(svc)

        # ۳) کاوش‌های UDP و پروتکل‌های ویژه
        if opt.get("snmp", True):
            community = opt.get("snmp_community") or "public"
            for comm in [community] + ([] if community != "public" else []):
                snmp = probe.snmp_probe(ip, comm, timeout=1.6)
                if snmp:
                    dev["snmp"] = snmp
                    services.append({"port": 161, "proto": "udp", "service": "SNMP", "snmp": snmp})
                    break
        try:
            ssdp = probe.ssdp_unicast(ip, timeout=1.2)
            if ssdp:
                dev.setdefault("ssdp", []).append(ssdp)
                if ssdp.get("location"):
                    self._fetch_upnp(ssdp["location"], hosts, ip)
        except Exception:
            pass
        dev["services"] = services

    # ----------------------------------------------------------------------------------
    def _scan_ports(self, ip: str, ports: list[int], timeout: float, workers: int) -> list[dict[str, Any]]:
        import socket as _socket

        open_ports: list[dict[str, Any]] = []
        lock = threading.Lock()

        def _try(port: int) -> None:
            if self.cancel.is_set():
                return
            s = None
            t0 = time.time()
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(timeout)
                rc = s.connect_ex((ip, port))
                if rc == 0:
                    rtt = (time.time() - t0) * 1000
                    with lock:
                        open_ports.append({
                            "port": port,
                            "service": TCP_SERVICE_NAMES.get(port),
                            "rtt_ms": round(rtt, 2),
                            "source": "اتصال TCP موفق (شاهد قطعی باز بودن پورت)",
                        })
            except OSError:
                pass
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

        chunk = 4000
        for i in range(0, len(ports), chunk):
            if self.cancel.is_set():
                break
            with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports[i:i + chunk])))) as ex:
                list(ex.map(_try, ports[i:i + chunk]))
        return sorted(open_ports, key=lambda x: x["port"])

    # ----------------------------------------------------------------------------------
    def _fetch_upnp(self, location: str, hosts: list[str], ip: str) -> None:
        try:
            allowed = set(hosts) | {ip}
            desc = probe.fetch_upnp_description(location, allowed)
            if desc:
                dev = self.devices.setdefault(ip, {})
                dev.setdefault("upnp", [])
                if not any(d.get("url") == location for d in dev["upnp"]):
                    dev["upnp"].append(desc)
        except Exception:
            pass

    # ----------------------------------------------------------------------------------
    # ادغام شواهد
    # ----------------------------------------------------------------------------------
    def _merge(self, ip: str, rec: dict[str, Any]) -> None:
        dev = self.devices.setdefault(ip, {"ip": ip, "alive": False, "evidence": [],
                                           "first_seen": time.time()})
        method = rec.get("method")
        if method in ACTIVE_METHODS:
            # شاهدِ «همین حالا زنده بودن» — پاسخ مستقیم از خود دستگاه
            dev["alive"] = True
            dev["alive_basis"] = rec.get("evidence") or method
            dev["last_seen"] = time.time()
        elif method == "dhcp_lease":
            # اجارهٔ DHCP فقط «شناسایی» است؛ ممکن است دستگاه اکنون خاموش باشد
            dev["lease_only"] = True
            dev.setdefault("alive_basis", rec.get("evidence"))
        if method and rec.get("evidence"):
            if not any(e.get("method") == method for e in dev["evidence"]):
                dev["evidence"].append({"method": method, "detail": rec.get("evidence")})
        if rec.get("mac") and not dev.get("mac"):
            dev["mac"] = rec["mac"]
            dev["mac_source"] = rec.get("evidence") or "خوانده‌شده از پاسخ دستگاه"
        if rec.get("rtt_ms") is not None:
            dev["rtt_ms"] = rec["rtt_ms"]
        if rec.get("open_tcp_ports"):
            merged = {p["port"]: p for p in dev.get("open_tcp_ports", [])}
            for item in rec["open_tcp_ports"]:
                if isinstance(item, dict):
                    merged[item["port"]] = item
                else:
                    port = int(item)
                    merged.setdefault(port, {
                        "port": port,
                        "service": TCP_SERVICE_NAMES.get(port),
                        "source": rec.get("evidence") or f"پاسخ سطح ۳ روی پورت {port}",
                    })
            dev["open_tcp_ports"] = [merged[k] for k in sorted(merged)]
        for key in ("evidence_extra", "state", "iface"):
            if rec.get(key):
                dev[key] = rec[key]
        if rec.get("closed_udp_ports"):
            dev["tcp_reset_evidence"] = True
        if method == "dhcp_lease":
            dev["dhcp_hostname"] = rec.get("dhcp_hostname") or dev.get("dhcp_hostname")
            dev["dhcp_lease_path"] = rec.get("lease_path")

    # ----------------------------------------------------------------------------------
    # ساخت رکورد نهایی دستگاه (شامل جدول واقعیت‌ها با منبع هرکدام)
    # ----------------------------------------------------------------------------------
    def _build_device(self, ip: str, gateway: str | None, local_ips: list[str]) -> dict[str, Any]:
        dev = self.devices[ip]
        if dev.get("alive"):
            status = "online"
        elif dev.get("lease_only"):
            status = "dhcp_only"
        else:
            status = "unknown"
        out: dict[str, Any] = {
            "ip": ip,
            "status": status,
            "alive_basis": dev.get("alive_basis"),
            "is_gateway": gateway == ip,
            "is_self": ip in local_ips,
            "mac": dev.get("mac"),
            "mac_source": dev.get("mac_source"),
            "first_seen": dev.get("first_seen"),
            "last_seen": dev.get("last_seen"),
            "rtt_ms": dev.get("rtt_ms"),
            "open_tcp_ports": sorted(
                [x if isinstance(x, dict) else {
                    "port": int(x), "service": TCP_SERVICE_NAMES.get(int(x)),
                    "source": "پاسخ سطح ۳ (SYN/ACK)"} for x in dev.get("open_tcp_ports", [])],
                key=lambda x: x["port"]),
            "services": dev.get("services", []),
            "evidence": dev.get("evidence", []),
            "evidence_count": len(dev.get("evidence", [])),
            "facts": [],
            "aliases": [],
            "inferences": [],
            "notes": [],
            "raw": {k: v for k, v in dev.items() if k in (
                "http", "tls", "ssh", "snmp", "ipp", "upnp", "ssdp", "mdns", "netbios",
                "ws_discovery", "rtsp", "banners", "dhcp_lease_path", "dhcp_hostname",
                "reverse_dns", "printer_ports")},
        }
        facts = out["facts"]

        def add(key: str, value: Any, source: str | None, certain: bool = True) -> None:
            if value in (None, "", [], {}):
                return
            facts.append({"key": key, "value": value, "source": source, "certain": certain})

        # MAC + سازنده
        mac = dev.get("mac")
        if mac:
            oui = self.oui.lookup(mac)
            out["mac_vendor"] = oui.get("vendor")
            out["mac_vendor_source"] = oui.get("source")
            out["mac_vendor_certain"] = oui.get("certain")
            out["mac_is_random"] = oui.get("is_locally_administered") and not oui.get("is_virtual")
            out["is_virtual_machine"] = oui.get("is_virtual")
            add("آدرس MAC", mac, dev.get("mac_source"))
            if oui.get("vendor"):
                add("سازندهٔ کارت شبکه (OUI)", oui["vendor"], oui.get("source"), oui.get("certain", True))
            if oui.get("note"):
                out["notes"].append(oui["note"])
            if oui.get("is_virtual"):
                add("نوع مجازی‌سازی", oui["virtual_kind"], "شناسهٔ ثبت‌شدهٔ IEEE برای مجازی‌سازها")

        # نشانی IPv6 (از جدول همسایگی هسته، با تطبیق MAC واقعی)
        v6 = dev.get("ipv6_neighbour")
        if v6 and v6.get("addresses"):
            add("نشانی IPv6 (از جدول همسایگی هسته)",
                ", ".join(sorted(set(v6["addresses"]))[:6]), v6.get("evidence"))

        # نام‌ها
        names: list[str] = []
        r = dev.get("reverse_dns")
        if r:
            names.append(r)
            add("نام میزبان (DNS معکوس)", r, "پرس‌وجوی PTR از سرور DNS شبکه")
            out["aliases"].append({"name": r, "source": "DNS معکوس"})
        nb = dev.get("netbios") or {}
        for n in nb.get("netbios_names", []):
            if n and n not in names:
                names.append(n)
        if nb.get("netbios_names"):
            add("نام NetBIOS", ", ".join(nb["netbios_names"]),
                "پاسخ NetBIOS Node Status (پورت ۱۳۷/udp)")
            out["aliases"].append({"name": nb["netbios_names"][0], "source": "NetBIOS NS"})
        if nb.get("workgroup"):
            add("گروه کاری/دامنه", nb["workgroup"], "پاسخ NetBIOS Node Status")
        lease_name = dev.get("dhcp_hostname")
        if lease_name:
            add("نام ثبت‌شده در DHCP", lease_name,
                f"فایل اجارهٔ DHCP ({dev.get('dhcp_lease_path', 'نامشخص')})")
            if lease_name not in names:
                names.append(lease_name)
                out["aliases"].append({"name": lease_name, "source": "اجارهٔ DHCP"})
        for entry in dev.get("mdns", []):
            for n in (entry.get("names") or []):
                host = n.split(".")[0]
                if host and host not in names:
                    names.append(host)
                    add("نام میزبان (mDNS)", n, "پاسخ mDNS معکوس (Pentest/Bonjour)")
                    out["aliases"].append({"name": n, "source": "mDNS"})
        out["name"] = names[0] if names else None
        out["all_names"] = names

        # SNMP
        snmp = dev.get("snmp")
        if snmp:
            vals = snmp.get("values", {})
            add("سیستم‌عامل/مدل (SNMP sysDescr)", vals.get("sysDescr"), "پاسخ SNMP از خود دستگاه")
            add("نام دستگاه (SNMP sysName)", vals.get("sysName"), "پاسخ SNMP از خود دستگاه")
            add("شمارهٔ سریال (SNMP)", vals.get("prtGeneralSerialNumber(1)"), "پاسخ SNMP")
            add("محل دستگاه (SNMP sysLocation)", vals.get("sysLocation"), "پاسخ SNMP")
            add("تماس (SNMP sysContact)", vals.get("sysContact"), "پاسخ SNMP")
            if vals.get("sysObjectID"):
                add("sysObjectID", vals["sysObjectID"], "پاسخ SNMP")
            out["snmp"] = snmp

        # NetBIOS MAC (تأییدکنندهٔ MAC)
        if nb.get("mac"):
            if dev.get("mac") and nb["mac"] != dev["mac"]:
                out["notes"].append(
                    f"MAC اعلام‌شده در NetBIOS ({nb['mac']}) با MAC جدول ARP ({dev['mac']}) تفاوت دارد؛ "
                    "برای اطمینان هر دو ثبت شده است."
                )
            elif not dev.get("mac"):
                out["mac"] = nb["mac"]
                add("آدرس MAC", nb["mac"], "پاسخ NetBIOS Node Status")

        # SSH
        ssh = dev.get("ssh")
        if ssh:
            add("نسخهٔ SSH", ssh.get("banner"), f"بنر SSH روی پورت {ssh.get('port')}")
            if ssh.get("ssh_software"):
                add("نرم‌افزار SSH", ssh["ssh_software"], f"بنر SSH روی پورت {ssh.get('port')}")

        # وب
        for entry in dev.get("http", [])[:6]:
            port = entry.get("port")
            if entry.get("server"):
                add(f"وب‌سرور (پورت {port})", entry["server"], f"هدر Server در پاسخ HTTP پورت {port}")
            if entry.get("title"):
                add(f"عنوان صفحهٔ وب (پورت {port})", entry["title"], f"محتوای HTML پورت {port}")
            if entry.get("powered_by"):
                add(f"فناوری وب (پورت {port})", entry["powered_by"], f"هدر X-Powered-By پورت {port}")
            if entry.get("device_header"):
                add("هدر اختصاصی دستگاه", entry["device_header"], f"هدر HTTP پورت {port}")
            if entry.get("html_meta"):
                add("متادیتای صفحه (HTML)", entry["html_meta"], f"متا تگ‌های HTML پورت {port}")
            if entry.get("www_authenticate"):
                add("نیازمند احراز هویت", entry["www_authenticate"], f"هدر WWW-Authenticate پورت {port}")

        # گواهی TLS
        for cert in dev.get("tls", []):
            cn = cert.get("subject_cn")
            if cn:
                add(f"نام گواهی TLS (پورت {cert.get('port')})", cn,
                    "گواهی TLS ارائه‌شده توسط دستگاه")
            if cert.get("subject_org"):
                add(f"سازمان گواهی TLS (پورت {cert.get('port')})", cert["subject_org"],
                    "گواهی TLS دستگاه")
            if cert.get("san_dns"):
                add(f"نام‌های جایگزین گواهی (SAN) پورت {cert.get('port')}",
                    ", ".join(cert["san_dns"][:12]), "گواهی TLS دستگاه")
            if cert.get("not_after"):
                add(f"انقضای گواهی (پورت {cert.get('port')})", cert["not_after"],
                    "گواهی TLS دستگاه")
            if cert.get("tls_version"):
                add(f"نسخهٔ TLS (پورت {cert.get('port')})",
                    f"{cert.get('tls_version')} / {cert.get('cipher')}", "مذاکرهٔ TLS واقعی")

        # UPnP
        for d in dev.get("upnp", [])[:3]:
            f = d.get("device", {})
            add("نام دستگاه (UPnP)", f.get("friendlyName"), d.get("source"))
            add("سازنده (UPnP)", f.get("manufacturer"), d.get("source"))
            add("مدل (UPnP)", f.get("modelName"), d.get("source"))
            if f.get("modelNumber"):
                add("شمارهٔ مدل (UPnP)", f.get("modelNumber"), d.get("source"))
            add("سریال (UPnP)", f.get("serialNumber"), d.get("source"))
            if f.get("deviceType"):
                add("نوع دستگاه (UPnP)", f.get("deviceType"), d.get("source"))
            if d.get("services"):
                add("سرویس‌های UPnP", ", ".join(d["services"][:10]), d.get("source"))

        # SSDP
        for s in dev.get("ssdp", [])[:4]:
            if s.get("server"):
                add("اعلام SSDP", s["server"], s.get("source") or "پاسخ SSDP")
            if s.get("st"):
                add("نوع SSDP (ST)", s["st"], s.get("source") or "پاسخ SSDP")

        # WS-Discovery / ONVIF
        for w in dev.get("ws_discovery", [])[:3]:
            if w.get("types"):
                add("نوع دستگاه (WS-Discovery)", w["types"], "پاسخ WS-Discovery از خود دستگاه")
            if w.get("onvif"):
                for k, v in w["onvif"].items():
                    add(f"ONVIF/{k}", v, "پاسخ WS-Discovery (Scopes سازمان ONVIF)")
            if w.get("scopes"):
                add("Scopes", " | ".join(w["scopes"][:8]), "پاسخ WS-Discovery")

        # IPP (چاپگر)
        ipp = dev.get("ipp")
        if ipp:
            attrs = ipp.get("ipp", {}).get("attributes", {})
            add("مدل چاپگر (IPP)", attrs.get("printer-make-and-model"),
                "پاسخ IPP Get-Printer-Attributes")
            add("نام چاپگر (IPP)", attrs.get("printer-name"), "پاسخ IPP")
            add("محل چاپگر (IPP)", attrs.get("printer-location"), "پاسخ IPP")
            add("سریال چاپگر (IPP)", attrs.get("printer-serial-number"), "پاسخ IPP")
            add("شناسهٔ دستگاه چاپگر", attrs.get("printer-device-id"), "پاسخ IPP")
            add("UUID چاپگر", attrs.get("printer-uuid"), "پاسخ IPP")

        # RTSP
        for r in dev.get("rtsp", [])[:3]:
            if r.get("rtsp_server"):
                add("سرویس‌دهندهٔ RTSP", r["rtsp_server"], f"پاسخ RTSP پورت {r.get('port')}")
            if r.get("rtsp_methods"):
                add("متدهای RTSP", r["rtsp_methods"], f"پاسخ RTSP پورت {r.get('port')}")

        # mDNS
        for entry in dev.get("mdns", []):
            if entry.get("services"):
                add("سرویس‌های mDNS", ", ".join(entry["services"]), "پاسخ mDNS (Bonjour)")
            if entry.get("txt"):
                add("اطلاعات TXT در mDNS", " | ".join(entry["txt"][:6]), "پاسخ mDNS")

        # پورت‌ها
        if out["open_tcp_ports"]:
            add("پورت‌های باز TCP",
                ", ".join(f"{p['port']}" + (f" ({p['service']})" if p.get("service") else "")
                          for p in out["open_tcp_ports"]),
                "اتصال TCP موفق (شاهد قطعی)")
        if dev.get("printer_ports"):
            add("پورت‌های چاپ خام", ", ".join(str(p) for p in dev["printer_ports"]),
                "پورت‌های اختصاصی چاپگر باز بودند")

        # ---------------- طبقه‌بندی نوع دستگاه (با ذکر مبنای هر ادعا) ----------------
        dtype, dsource, dcertain = self._classify(dev, out)
        out["device_type"] = dtype
        out["device_type_source"] = dsource
        out["device_type_certain"] = dcertain
        if dtype:
            add("نوع دستگاه", dtype, dsource, dcertain)

        # ---------------- استنتاج‌های احتمالی (به‌صراحت جدا و برچسب‌دار) ----------------
        out["inferences"] = self._inferences(dev, out)
        return out

    # ----------------------------------------------------------------------------------
    def _classify(self, dev: dict[str, Any], out: dict[str, Any]) -> tuple[str | None, str | None, bool]:
        """نوع دستگاه را فقط بر پایهٔ شاهدهای واقعی تعیین می‌کند (با ذکر مبنا)."""
        if out.get("is_self"):
            return "همین دستگاه (اسکنر)", "رابط شبکهٔ محلی همین برنامه", True
        if out.get("is_gateway"):
            return "دروازهٔ شبکه / روتر", "آدرس پیش‌فرض مسیریابی همین سیستم است", True

        for d in dev.get("upnp", []):
            dt = (d.get("device", {}) or {}).get("deviceType", "") or ""
            if "InternetGatewayDevice" in dt:
                return "روتر / مودم ADSL", "اعلام UPnP: InternetGatewayDevice", True
        for w in dev.get("ws_discovery", []):
            t = (w.get("types") or "") + " " + " ".join(w.get("scopes", []))
            if "NetworkVideoTransmitter" in t or "onvif" in t.lower():
                return "دوربین IP / دستگاه نظارت تصویری (ONVIF)", "اعلام WS-Discovery/ONVIF", True
            if "Printer" in t or "print" in t.lower():
                return "چاپگر شبکه", "اعلام WS-Discovery (PrintDevice)", True
            if "Scanner" in t:
                return "اسکنر شبکه", "اعلام WS-Discovery (ScannerDevice)", True
        if dev.get("ipp") or dev.get("printer_ports") or 631 in {p["port"] for p in out["open_tcp_ports"]}:
            return "چاپگر شبکه", "پاسخ پروتکل چاپ IPP/RAW از دستگاه", True
        if dev.get("rtsp"):
            return "دوربین IP / ضبط‌کنندهٔ تصویر", "پاسخ پروتکل RTSP روی پورت ۵۵۴", True
        snmp = dev.get("snmp") or {}
        descr = (snmp.get("values", {}) or {}).get("sysDescr") or ""
        if descr:
            low = descr.lower()
            if "printer" in low or "laserjet" in low:
                return "چاپگر شبکه", "sysDescr پاسخ SNMP", True
            if any(k in low for k in ("router", "switch", "gateway", "mikrotik", "routeros", "openwrt", "ubiquiti", "cisco ios")):
                return "روتر / سوییچ مدیریتی", "sysDescr پاسخ SNMP", True
            if "windows" in low:
                return "رایانهٔ ویندوزی", "sysDescr پاسخ SNMP", True
            if "linux" in low:
                return "دستگاه لینوکسی", "sysDescr پاسخ SNMP", True
            if "synology" in low:
                return "ذخیره‌ساز NAS", "sysDescr پاسخ SNMP", True
        ports = {p["port"] for p in out["open_tcp_ports"]}
        if {5000, 5001} & ports and 22 in ports:
            return "ذخیره‌ساز NAS (احتمالاً Synology)", "الگوی پورت‌های سرویس NAS", False
        return None, None, False

    def _inferences(self, dev: dict[str, Any], out: dict[str, Any]) -> list[dict[str, str]]:
        """موارد احتمالی — جدا از واقعیت‌های قطعی، با ذکر دلیل."""
        inf: list[dict[str, str]] = []
        ports = {p["port"] for p in out["open_tcp_ports"]}
        if 62078 in ports:
            inf.append({"claim": "به احتمال زیاد گوشی/تبلت اپل (iPhone/iPad)",
                        "basis": "پورت ۶۲۰۷۸ (lockdownd) باز است"})
        if {445, 139} & ports or 3389 in ports:
            inf.append({"claim": "به احتمال زیاد رایانهٔ ویندوزی",
                        "basis": "پورت‌های SMB/RDP باز هستند"})
        if 22 in ports and 80 not in ports and 443 not in ports:
            inf.append({"claim": "به احتمال زیاد دستگاه لینوکسی/توکار",
                        "basis": "فقط SSH باز است"})
        if {8008, 8009} & ports:
            inf.append({"claim": "به احتمال زیاد دستگاه Google Cast (Chromecast/اسپیکر هوشمند)",
                        "basis": "پورت‌های ۸۰۰۸/۸۰۰۹ باز هستند"})
        mac = out.get("mac")
        oui_vendor = (out.get("mac_vendor") or "")
        if mac and out.get("mac_is_random"):
            inf.append({"claim": "MAC تصادفی (Randomized) — سازنده از ثبت IEEE قابل تشخیص نیست",
                        "basis": "بیت Locally Administered در MAC روشن است"})
        if "Espressif" in oui_vendor:
            inf.append({"claim": "به احتمال زیاد دستگاه هوشمند خانگی IoT (ESP32/ESP8266)",
                        "basis": f"سازندهٔ OUI: {oui_vendor}"})
        if "Raspberry Pi" in oui_vendor:
            inf.append({"claim": "برد تک‌برد Raspberry Pi", "basis": f"سازندهٔ OUI: {oui_vendor}"})
        if "Apple" in oui_vendor and 62078 not in ports:
            inf.append({"claim": "دستگاه اپل (iPhone/iPad/Mac/Apple TV)",
                        "basis": "سازندهٔ MAC در ثبت IEEE: Apple"})
        return inf

    # ----------------------------------------------------------------------------------
    def _self_facts(self, ip: str, local_ip: str | None) -> None:
        dev = self.devices[ip]
        dev["is_self"] = True
        if not dev.get("mac"):
            for i in netinfo.list_interfaces():
                if i.get("mac") and not i.get("is_loopback"):
                    dev["mac"] = i["mac"]
                    dev["mac_source"] = "رابط شبکهٔ همین دستگاه (کارت شبکهٔ محلی)"
                    break
        dev["reverse_dns"] = dev.get("reverse_dns") or netinfo.hostname_of_self()
        dev["local_listeners"] = discovery.listen_sockets_local()
        dev["alive"] = True

    # ----------------------------------------------------------------------------------
    def _finish(self, hosts: list[str], iface: dict[str, Any], local_ip: str | None,
                gateway: str | None, target_name: str, cancelled: bool = False) -> dict[str, Any]:
        devices = [self._build_device(ip, gateway, [local_ip] if local_ip else [])
                   for ip in sorted(self.devices.keys(), key=lambda x: tuple(int(p) for p in x.split(".")))]
        finished = time.time()
        # دستگاه‌های بدون MAC: صریحاً توضیح داده می‌شود (بدون حدس)
        for d in devices:
            if not d.get("mac") and d.get("status") != "unknown":
                if not self.caps.arp:
                    reason = ("اسکن ARP خام در دسترس نبود (بدون دسترسی root) و دستگاه هم به "
                              "NetBIOS پاسخ نداد")
                else:
                    reason = "دستگاه به پرس‌وجوی ARP و NetBIOS پاسخ نداد (مسیر L2 متفاوت)"
                d.setdefault("notes", []).append(f"آدرس MAC در دسترس نبود: {reason}")
                d["mac_unavailable_reason"] = reason
        online = [d for d in devices if d.get("status") in ("online", "dhcp_only")]
        result = {
            "scan": {
                "started": self.started,
                "finished": finished,
                "duration_sec": round(finished - self.started, 2),
                "target": target_name,
                "interface": iface.get("name"),
                "local_ip": local_ip,
                "gateway": gateway,
                "hosts_scanned": len(hosts),
                "cancelled": cancelled,
                "capabilities": self.caps.as_dict(),
                "options": {k: v for k, v in self.opt.items() if k != "oui_paths"},
                "stats": self.stats,
                "oui": {"entries": self.oui.size, "sources": self.oui.sources,
                        "fallback_only": self.oui.is_fallback_only},
            },
            "devices": devices,
            "summary": {
                "devices_online": len(online),
                "with_mac": len([d for d in online if d.get("mac")]),
                "with_hostname": len([d for d in online if d.get("name")]),
                "open_ports_total": sum(len(d.get("open_tcp_ports", [])) for d in online),
                "device_types": self._type_counts(online),
            },
            "warnings": self.warnings,
        }
        self.emit({"type": "done", "result": result})
        return result

    @staticmethod
    def _type_counts(devices: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in devices:
            t = d.get("device_type") or "نامشخص (بدون شاهد کافی)"
            counts[t] = counts.get(t, 0) + 1
        return counts

    # ----------------------------------------------------------------------------------
    def _load_private_ranges(self) -> list[str]:
        # محدوده‌ای که کاوش فعال در آن انجام می‌شود: آدرس‌های خصوصی + محلی
        return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                "100.64.0.0/10", "127.0.0.0/8", "fc00::/7"]

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            return False
        return any(addr in ipaddress.IPv4Network(cidr) for cidr in self._load_private_ranges())

    def _in_hosts(self, ip: str, hosts: list[str]) -> bool:
        if not self.hosts_set:
            self.hosts_set = set(hosts)
        return ip in self.hosts_set

    @staticmethod
    def _is_self(ip: str, local_ips: list[str]) -> bool:
        return ip in local_ips


def run_scan(options: dict[str, Any], emit: Callable[[dict[str, Any]], None] | None = None,
             cancel: threading.Event | None = None) -> dict[str, Any]:
    return ScanEngine(options, emit, cancel).run()
