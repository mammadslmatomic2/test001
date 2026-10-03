"""
netinfo.py — کشف رابط‌های شبکه (Network interfaces) و زیرشبکه‌های محلی به‌صورت دقیق.

Interfaces are read from the operating system itself (iproute2 on Linux, ifconfig on
macOS/BSD, PowerShell on Windows).  Nothing here is guessed: every value comes from a
kernel/OS source, and the source name is kept next to the value.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import sys
from typing import Any


def _run(cmd: list[str], timeout: float = 8.0) -> str:
    """Run a command and return stdout (empty string on any failure)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return p.stdout or ""
    except Exception:
        return ""


def _mac_is_valid(mac: str | None) -> bool:
    if not mac:
        return False
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "ff:ff:ff:ff:ff:ff"):
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac))


def _netmask_to_prefix(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return None


# --------------------------------------------------------------------------------------
# Linux (iproute2)
# --------------------------------------------------------------------------------------
def _linux_interfaces() -> list[dict[str, Any]]:
    out = _run(["ip", "-j", "addr", "show"])
    ifaces: list[dict[str, Any]] = []
    if out.strip():
        try:
            data = json.loads(out)
        except Exception:
            data = []
        for item in data:
            name = item.get("ifname", "?")
            flags = item.get("flags", []) or []
            addrs4, addrs6 = [], []
            for a in item.get("addr_info", []) or []:
                if a.get("family") == "inet":
                    prefix = a.get("prefixlen")
                    ip = a.get("local")
                    if ip and prefix is not None:
                        net = ipaddress.IPv4Interface(f"{ip}/{prefix}")
                        addrs4.append(
                            {
                                "address": ip,
                                "prefixlen": prefix,
                                "netmask": str(net.network.netmask),
                                "broadcast": str(net.network.broadcast_address),
                                "cidr": str(net.network),
                            }
                        )
                elif a.get("family") == "inet6":
                    ip = a.get("local")
                    prefix = a.get("prefixlen")
                    if ip:
                        addrs6.append(
                            {
                                "address": ip.split("%")[0],
                                "prefixlen": prefix,
                                "scope": a.get("scope"),
                                "temporary": bool(a.get("temporary")),
                            }
                        )
            ifaces.append(
                {
                    "name": name,
                    "mac": (item.get("address") or "").lower() or None,
                    "mtu": item.get("mtu"),
                    "state": item.get("operstate"),
                    "is_up": "UP" in flags,
                    "is_loopback": "LOOPBACK" in flags or name == "lo",
                    "ipv4": addrs4,
                    "ipv6": addrs6,
                    "source": "ip -j addr show (kernel)",
                }
            )
        return ifaces

    # Older iproute2 without JSON support: parse the text output.
    text = _run(["ip", "addr", "show"])
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+([^:@]+)[:@]", line)
        if m:
            current = {
                "name": m.group(1),
                "mac": None,
                "is_up": "UP" in line and "state UP" in line,
                "is_loopback": m.group(1) == "lo",
                "ipv4": [],
                "ipv6": [],
                "source": "ip addr show (kernel)",
            }
            ifaces.append(current)
            continue
        if current is None:
            continue
        mm = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
        if mm:
            current["mac"] = mm.group(1).lower()
        m4 = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m4:
            net = ipaddress.IPv4Interface(f"{m4.group(1)}/{m4.group(2)}")
            current["ipv4"].append(
                {
                    "address": m4.group(1),
                    "prefixlen": int(m4.group(2)),
                    "netmask": str(net.network.netmask),
                    "broadcast": str(net.network.broadcast_address),
                    "cidr": str(net.network),
                }
            )
    return ifaces


# --------------------------------------------------------------------------------------
# macOS / BSD (ifconfig)
# --------------------------------------------------------------------------------------
def _bsd_interfaces() -> list[dict[str, Any]]:
    text = _run(["ifconfig", "-a"])
    ifaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        m = re.match(r"^(\S+):\s+flags=", line)
        if m:
            current = {
                "name": m.group(1),
                "mac": None,
                "is_up": "UP" in line,
                "is_loopback": "LOOPBACK" in line,
                "ipv4": [],
                "ipv6": [],
                "source": "ifconfig -a (OS)",
            }
            ifaces.append(current)
            continue
        if current is None:
            continue
        me = re.search(r"ether\s+([0-9a-fA-F:]{17})", line)
        if me:
            current["mac"] = me.group(1).lower()
        m4 = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", line)
        if m4:
            mask = m4.group(2)
            if mask.startswith("0x"):
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            prefix = _netmask_to_prefix(mask)
            if prefix is not None:
                net = ipaddress.IPv4Interface(f"{m4.group(1)}/{prefix}")
                current["ipv4"].append(
                    {
                        "address": m4.group(1),
                        "prefixlen": prefix,
                        "netmask": mask,
                        "broadcast": str(net.network.broadcast_address),
                        "cidr": str(net.network),
                    }
                )
    return ifaces


# --------------------------------------------------------------------------------------
# Windows (PowerShell)
# --------------------------------------------------------------------------------------
def _windows_interfaces() -> list[dict[str, Any]]:
    ps_addr = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength,InterfaceAlias,InterfaceIndex | ConvertTo-Json -Compress",
        ],
        timeout=20,
    )
    ps_link = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object Name,MacAddress,Status,ifIndex | ConvertTo-Json -Compress",
        ],
        timeout=20,
    )

    def _as_list(raw: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw) if raw.strip() else []
        except Exception:
            return []
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []

    links = {str(x.get("ifIndex")): x for x in _as_list(ps_link)}
    ifaces: dict[str, dict[str, Any]] = {}
    for a in _as_list(ps_addr):
        name = a.get("InterfaceAlias") or "?"
        idx = str(a.get("InterfaceIndex"))
        link = links.get(idx, {})
        iface = ifaces.setdefault(
            name,
            {
                "name": name,
                "mac": (link.get("MacAddress") or "").replace("-", ":").lower() or None,
                "is_up": (link.get("Status") == "Up"),
                "is_loopback": "loopback" in name.lower(),
                "ipv4": [],
                "ipv6": [],
                "source": "PowerShell Get-NetIPAddress/Get-NetAdapter (OS)",
            },
        )
        ip = a.get("IPAddress")
        prefix = a.get("PrefixLength")
        if ip and prefix is not None and not ip.startswith("127."):
            net = ipaddress.IPv4Interface(f"{ip}/{prefix}")
            iface["ipv4"].append(
                {
                    "address": ip,
                    "prefixlen": int(prefix),
                    "netmask": str(net.network.netmask),
                    "broadcast": str(net.network.broadcast_address),
                    "cidr": str(net.network),
                }
            )
    return list(ifaces.values())


def list_interfaces() -> list[dict[str, Any]]:
    """Return every network interface reported by the OS (with the data source kept)."""
    if sys.platform.startswith("linux"):
        ifaces = _linux_interfaces()
    elif sys.platform == "darwin" or "bsd" in sys.platform:
        ifaces = _bsd_interfaces()
    elif sys.platform.startswith("win"):
        ifaces = _windows_interfaces()
    else:
        ifaces = []

    for i in ifaces:
        if not _mac_is_valid(i.get("mac")):
            i["mac"] = None
    return ifaces


def get_gateway() -> dict[str, Any] | None:
    """Default gateway, straight from the routing table."""
    out = _run(["ip", "-j", "route", "show", "default"])
    if out.strip():
        try:
            data = json.loads(out)
            if data:
                r = data[0]
                return {"gateway": r.get("gateway"), "device": r.get("dev"), "source": "ip route (kernel)"}
        except Exception:
            pass
    text = _run(["ip", "route", "show", "default"]) or _run(["netstat", "-rn"])
    m = re.search(r"default(?:\s+via)?\s+(\d+\.\d+\.\d+\.\d+)(?:\s+dev\s+(\S+))?", text)
    if m:
        return {"gateway": m.group(1), "device": m.group(2), "source": "routing table (kernel)"}
    if sys.platform.startswith("win"):
        ps = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 NextHop,InterfaceAlias | ConvertTo-Json -Compress)",
            ],
            timeout=20,
        )
        try:
            r = json.loads(ps)
            return {"gateway": r.get("NextHop"), "device": r.get("InterfaceAlias"), "source": "Get-NetRoute (OS)"}
        except Exception:
            pass
    return None


def local_ipv4s(ifaces: list[dict[str, Any]] | None = None) -> list[str]:
    ifaces = ifaces if ifaces is not None else list_interfaces()
    return [a["address"] for i in ifaces for a in i.get("ipv4", [])]


def hosts_in(target: str, max_hosts: int = 4096) -> tuple[list[str], str | None]:
    """
    Expand a target expression into a list of IPv4 addresses.

    Accepts:  192.168.1.0/24 | 192.168.1.10 | 192.168.1.10-192.168.1.60 | ranges by comma.
    NOTE: /31 and /32 are handled correctly, and the network/broadcast addresses are
    only skipped for networks where they are genuinely unusable.
    """
    hosts: list[str] = []
    warning = None
    for part in re.split(r"[,\s]+", target.strip()):
        if not part:
            continue
        try:
            if "-" in part and "/" not in part:
                a, b = part.split("-", 1)
                start = int(ipaddress.IPv4Address(a.strip()))
                b = b.strip()
                end = int(ipaddress.IPv4Address(b)) if b.count(".") == 3 else int(
                    ipaddress.IPv4Address(a.strip().rsplit(".", 1)[0] + "." + b)
                )
                if end < start:
                    start, end = end, start
                hosts.extend(str(ipaddress.IPv4Address(i)) for i in range(start, end + 1))
                continue
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                if net.version != 4:
                    continue
                if net.prefixlen >= 31:
                    hosts.extend(str(h) for h in net)
                else:
                    count = net.num_addresses - 2
                    if count > max_hosts:
                        warning = (
                            f"شبکه {net} شامل {count} میزبان است؛ اسکن به {max_hosts} آدرس اول محدود شد."
                        )
                        hosts.extend(str(h) for h in list(net.hosts())[:max_hosts])
                    else:
                        hosts.extend(str(h) for h in net.hosts())
                continue
            ipaddress.IPv4Address(part)  # validate
            hosts.append(part)
        except Exception:
            raise ValueError(f"هدف نامعتبر: {part!r}")
    deduped = list(dict.fromkeys(hosts))
    if len(deduped) > max_hosts:
        warning = f"تعداد آدرس‌ها به {max_hosts} مورد محدود شد."
        deduped = deduped[:max_hosts]
    return deduped, warning


def auto_targets() -> list[dict[str, Any]]:
    """Suggested scan targets: every non-loopback IPv4 network this machine is on."""
    out = []
    for i in list_interfaces():
        if i.get("is_loopback"):
            continue
        for a in i.get("ipv4", []):
            out.append(
                {
                    "cidr": a["cidr"],
                    "address": a["address"],
                    "interface": i["name"],
                    "mac": i.get("mac"),
                    "prefixlen": a["prefixlen"],
                }
            )
    return out


def hostname_of_self() -> str | None:
    try:
        return socket.gethostname()
    except Exception:
        return None
