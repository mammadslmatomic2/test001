/* app.js — منطق رابط کاربری اسکنر شبکه */
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => (s === null || s === undefined) ? "" :
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let STATE = {
  context: null,
  scanId: null,
  source: null,
  devices: new Map(),   // ip -> device
  result: null,
  selected: null,
  running: false,
};

const STATUS_LABEL = {
  online: ["ok", "آنلاین"],
  dhcp_only: ["warn", "شناسایی از DHCP"],
  unknown: ["info", "نامعلوم"],
};

/* ------------------------------------------------------------------ context */
async function loadContext() {
  try {
    const r = await fetch("/api/context");
    const ctx = await r.json();
    STATE.context = ctx;
    renderCapPills(ctx);
    renderInterfaces(ctx);
    renderTargets(ctx);
    renderOuiNote(ctx);
  } catch (e) {
    logLine("خطا در دریافت اطلاعات سیستم: " + e, "err");
  }
}

function renderCapPills(ctx) {
  const c = ctx.capabilities || {};
  const pill = (ok, label, title) =>
    `<span class="pill ${ok ? "ok" : "warn"}" title="${esc(title || "")}">${ok ? "✔" : "✘"} ${label}</span>`;
  $("capPills").innerHTML = [
    pill(c.root, "دسترسی root", "بدون root: اسکن ARP/ICMP/TCP-SYN خام فعال نیست"),
    pill(c.arp_raw, "ARP خام", "قوی‌ترین روش کشف در شبکهٔ محلی"),
    pill(c.icmp_raw, "ICMP خام", "پینگ واقعی سطح سوکت"),
    pill(c.tcp_syn_raw, "TCP SYN", "اسکن سریع پورت"),
    `<span class="pill info">نسخه ${esc(ctx.version || "")}</span>`,
  ].join("");
  if (ctx.oui) {
    $("capPills").insertAdjacentHTML("beforeend",
      `<span class="pill ${ctx.oui.fallback_only ? "warn" : "ok"}" title="${esc((ctx.oui.sources || []).join(" | "))}">
        ${ctx.oui.fallback_only ? "واژه‌نامهٔ داخلی" : "فهرست رسمی IEEE"} (${ctx.oui.entries} رکورد)</span>`);
  }
}

function renderInterfaces(ctx) {
  const sel = $("iface");
  sel.innerHTML = (ctx.interfaces || [])
    .filter((i) => !i.is_loopback)
    .map((i) => {
      const ips = (i.ipv4 || []).map((a) => `${a.address}/${a.prefixlen}`).join(", ") || "بدون IPv4";
      const def = (ctx.gateway && ctx.gateway.device === i.name) ? " — پیش‌فرض" : "";
      return `<option value="${esc(i.name)}">${esc(i.name)} — ${esc(ips)}${def}</option>`;
    }).join("");
}

function renderTargets(ctx) {
  const dl = $("targets");
  dl.innerHTML = (ctx.suggested_targets || [])
    .map((s) => `<option value="${esc(s.cidr)}">${esc(s.interface)} (${esc(s.address)})</option>`).join("");
  const first = (ctx.suggested_targets || [])[0];
  if (first && !$("target").value) {
    $("target").value = first.cidr;
  }
  const info = [];
  if (ctx.hostname) info.push(`نام این دستگاه: ${ctx.hostname}`);
  if (ctx.gateway && ctx.gateway.gateway) info.push(`دروازه: ${ctx.gateway.gateway}`);
  $("targetHint").textContent = info.join(" | ");
}

function renderOuiNote(ctx) {
  if (ctx.oui && ctx.oui.fallback_only) {
    logLine("فهرست کامل IEEE OUI در دسترس نیست؛ از واژه‌نامهٔ کوچک داخلی استفاده می‌شود. " +
      "برای دقت کامل، دکمهٔ «به‌روزرسانی فهرست IEEE» را بزنید.", "warn");
  }
}

/* ------------------------------------------------------------------ scanning */
async function startScan() {
  if (STATE.running) return;
  const payload = {
    target: $("target").value.trim(),
    interface: $("iface").value || null,
    ports: $("ports").value,
    extra_ports: $("extraPorts").value.trim(),
    mode: $("mode").value,
    tcp_timeout: parseFloat($("tcpTimeout").value || "0.7"),
    workers: parseInt($("workers").value || "256", 10),
    host_workers: parseInt($("hostWorkers").value || "16", 10),
    max_hosts: parseInt($("maxHosts").value || "4096", 10),
    snmp: $("snmpOn").value === "1",
    snmp_community: $("snmpCommunity").value || "public",
  };
  if (payload.ports === "all" && !confirm("اسکن تمام ۶۵۵۳۵ پورت روی همهٔ آدرس‌ها زمان‌بر است. ادامه می‌دهید؟")) return;

  resetUI();
  let resp;
  try {
    resp = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
  } catch (e) { logLine("ارتباط با سرور برقرار نشد: " + e, "err"); return; }
  const data = await resp.json();
  if (!resp.ok) { logLine(data.error || "خطای شروع اسکن", "err"); return; }

  STATE.scanId = data.scan_id;
  STATE.running = true;
  $("startBtn").disabled = true;
  $("stopBtn").disabled = false;
  logLine("اسکن آغاز شد. شناسه: " + STATE.scanId);
  openStream(STATE.scanId);
}

function openStream(id) {
  if (STATE.source) STATE.source.close();
  const es = new EventSource("/api/stream/" + id);
  STATE.source = es;
  es.onmessage = (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch { return; }
    handleEvent(data);
  };
  es.onerror = () => {
    es.close();
    if (STATE.running) {
      setTimeout(() => { if (STATE.running) openStream(id); }, 1500);
    }
  };
}

function handleEvent(ev) {
  switch (ev.type) {
    case "phase":
      $("bar").value = ev.pct || 0;
      $("phaseText").innerHTML = `<span class="spin"></span> ${esc(ev.message)}`;
      break;
    case "log":
      logLine(ev.message, ev.level === "warn" ? "warn" : (ev.level === "error" ? "err" : ""));
      break;
    case "context":
      renderContext(ev.context);
      break;
    case "device_update":
      STATE.devices.set(ev.device.ip, ev.device);
      renderStats();
      renderTable();
      if (STATE.selected === ev.device.ip) renderDetail(ev.device);
      break;
    case "error":
      logLine(ev.message, "err");
      break;
    case "done":
      finishScan(ev.result);
      break;
  }
}

function finishScan(result) {
  STATE.running = false;
  STATE.result = result;
  $("startBtn").disabled = false;
  $("stopBtn").disabled = true;
  $("bar").value = 100;
  $("phaseText").textContent = "اسکن کامل شد.";
  if (STATE.source) { STATE.source.close(); STATE.source = null; }
  ["jsonBtn", "csvBtn", "htmlBtn"].forEach((b) => { $(b).disabled = false; });
  if (result && result.devices) {
    result.devices.forEach((d) => STATE.devices.set(d.ip, d));
  }
  renderStats();
  renderTable();
  (result && result.warnings || []).forEach((w) => logLine("⚠️ " + w, "warn"));
  logLine(`پایان اسکن: ${result && result.scan ? result.scan.duration_sec + " ثانیه" : ""}`);
}

function stopScan() {
  if (!STATE.scanId) return;
  fetch("/api/stop/" + STATE.scanId, { method: "POST" }).then(() => logLine("درخواست توقف ارسال شد…", "warn"));
}

function renderContext(ctx) {
  if (!ctx) return;
  logLine(`گستره: ${ctx.target} (${ctx.host_count} آدرس) | رابط ${ctx.interface && ctx.interface.name} | ` +
    `IP محلی ${ctx.local_ip} | دروازه ${ctx.gateway || "—"}`);
  if (ctx.capabilities && !ctx.capabilities.arp_raw) {
    logLine("هشدار: اسکن ARP خام فعال نیست (بدون root). برخی دستگاه‌ها ممکن است فقط با MAC شناسایی نشوند.", "warn");
  }
  renderStats();
}

/* ------------------------------------------------------------------ rendering */
function renderStats() {
  const r = STATE.result;
  const devs = [...STATE.devices.values()];
  const online = devs.filter((d) => d.status === "online").length;
  const withMac = devs.filter((d) => d.mac).length;
  const withName = devs.filter((d) => d.name).length;
  const ports = devs.reduce((a, d) => a + ((d.open_tcp_ports || []).length), 0);
  const stats = [
    ["دستگاه‌های آنلاین", online],
    ["کل ردیف‌ها", devs.length],
    ["دارای MAC", withMac],
    ["دارای نام", withName],
    ["پورت‌های باز", ports],
    ["آدرس‌های بررسی‌شده", r && r.scan ? r.scan.hosts_scanned : "—"],
  ];
  $("statCards").innerHTML = stats.map(([k, v]) =>
    `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("");
  const types = new Set(devs.map((d) => d.device_type).filter(Boolean));
  const cur = $("typeFilter").value;
  $("typeFilter").innerHTML = `<option value="">همه</option>` +
    [...types].sort().map((t) => `<option value="${esc(t)}"${t === cur ? " selected" : ""}>${esc(t)}</option>`).join("");
}

function filteredDevices() {
  const q = $("q").value.trim().toLowerCase();
  const st = $("statusFilter").value;
  const ty = $("typeFilter").value;
  let list = [...STATE.devices.values()];
  if (st) list = list.filter((d) => d.status === st);
  if (ty) list = list.filter((d) => (d.device_type || "") === ty);
  if (q) {
    list = list.filter((d) => {
      const hay = [
        d.ip, d.name, d.mac, d.mac_vendor, d.device_type,
        (d.all_names || []).join(" "),
        (d.open_tcp_ports || []).map((p) => p.port + " " + (p.service || "")).join(" "),
        JSON.stringify(d.facts || []),
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }
  const sortBy = $("sortBy").value;
  const ipKey = (ip) => ip.split(".").reduce((a, x) => a * 256 + parseInt(x, 10), 0);
  list.sort((a, b) => {
    if (sortBy === "ports") return (b.open_tcp_ports || []).length - (a.open_tcp_ports || []).length;
    if (sortBy === "evidence") return (b.evidence_count || 0) - (a.evidence_count || 0);
    if (sortBy === "name") return String(a.name || "~").localeCompare(String(b.name || "~"), "fa");
    return ipKey(a.ip) - ipKey(b.ip);
  });
  return list;
}

function renderTable() {
  const list = filteredDevices();
  const tbody = $("rows");
  $("emptyMsg").style.display = list.length ? "none" : "block";
  if (!list.length) { tbody.innerHTML = ""; return; }
  tbody.innerHTML = list.map((d, i) => {
    const [cls, label] = STATUS_LABEL[d.status] || ["info", d.status];
    const ports = (d.open_tcp_ports || []);
    const portHtml = ports.slice(0, 8).map((p) =>
      `<span class="chip" title="${esc(p.service || "")} — ${esc(p.source || "")}">${p.port}${p.service ? " · " + esc(shortSvc(p.service)) : ""}</span>`).join(" ") +
      (ports.length > 8 ? ` <span class="muted tiny">+${ports.length - 8}</span>` : "");
    const names = [d.name].concat((d.all_names || []).filter((n) => n !== d.name)).filter(Boolean);
    return `<tr data-ip="${esc(d.ip)}" class="${STATE.selected === d.ip ? "selected" : ""}">
      <td class="muted tiny">${i + 1}</td>
      <td><b class="mono">${esc(d.ip)}</b>
        ${d.is_gateway ? '<span class="badge info">دروازه</span>' : ""}
        ${d.is_self ? '<span class="badge info">همین دستگاه</span>' : ""}
        <div><span class="badge ${cls}">${esc(label)}</span></div></td>
      <td>${names.length ? esc(names[0]) : '<span class="muted">—</span>'}
        ${names.length > 1 ? `<div class="muted tiny">${esc(names.slice(1, 3).join("، "))}</div>` : ""}</td>
      <td><span class="mono tiny">${d.mac ? esc(d.mac) : '<span class="muted">در دسترس نیست</span>'}</span>
        <div class="muted tiny">${esc(d.mac_vendor || "سازنده نامشخص")}
        ${d.mac_is_random ? '<span class="badge warn">MAC تصادفی</span>' : ""}
        ${d.is_virtual_machine ? '<span class="badge info">مجازی</span>' : ""}</div></td>
      <td>${d.device_type ? esc(d.device_type) : '<span class="muted">نامشخص</span>'}
        ${d.device_type ? `<div><span class="badge ${d.device_type_certain ? "ok" : "warn"}">${d.device_type_certain ? "مبتنی بر شاهد" : "استنتاجی"}</span></div>` : ""}</td>
      <td>${portHtml || '<span class="muted">—</span>'}</td>
      <td>${d.evidence_count || 0}</td>
    </tr>`;
  }).join("");
  tbody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", () => {
      STATE.selected = tr.dataset.ip;
      renderTable();
      renderDetail(STATE.devices.get(tr.dataset.ip));
      $("detailCard").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

function shortSvc(s) { return String(s).replace(/\s*\(.*?\)\s*/g, "").slice(0, 22); }

function renderDetail(d) {
  if (!d) { $("detail").innerHTML = '<div class="empty">دستگاهی انتخاب نشده است.</div>'; return; }
  const facts = (d.facts || []).map((f) => `<tr>
      <td>${esc(f.key)}</td>
      <td>${esc(typeof f.value === "object" ? JSON.stringify(f.value) : f.value)}</td>
      <td class="src">${esc(f.source || "—")}</td>
      <td><span class="badge ${f.certain ? "ok" : "warn"}">${f.certain ? "قطعی" : "غیرقطعی"}</span></td>
    </tr>`).join("") || '<tr><td colspan="4" class="muted">اطلاعات تکمیلی ثبت نشد.</td></tr>';
  const ev = (d.evidence || []).map((e) => `<li>${esc(e.detail)} <span class="src">(${esc(e.method)})</span></li>`).join("")
    || '<li class="muted">—</li>';
  const inf = (d.inferences || []).map((x) =>
    `<li><b>${esc(x.claim)}</b><div class="src">دلیل: ${esc(x.basis)}</div></li>`).join("");
  const notes = (d.notes || []).map((n) => `<div class="note">ℹ️ ${esc(n)}</div>`).join("");
  const ports = (d.open_tcp_ports || []).map((p) =>
    `<span class="chip">${p.port}${p.service ? " · " + esc(shortSvc(p.service)) : ""}${p.rtt_ms ? " · " + p.rtt_ms + "ms" : ""}</span>`).join(" ")
    || '<span class="muted">پورت بازی یافت نشد</span>';
  const raw = JSON.stringify(d.raw || {}, null, 2);

  $("detail").innerHTML = `
    <div class="flex" style="justify-content:space-between">
      <div>
        <div style="font-size:18px;font-weight:800" class="mono">${esc(d.ip)}</div>
        <div class="muted">${esc(d.name || "بدون نام")} — ${esc(d.device_type || "نوع نامشخص")}</div>
      </div>
      <div class="pillrow">
        ${d.is_gateway ? '<span class="pill info">دروازهٔ شبکه</span>' : ""}
        ${d.is_self ? '<span class="pill info">همین دستگاه</span>' : ""}
        <span class="pill ${(STATUS_LABEL[d.status] || ["info"])[0]}">${esc((STATUS_LABEL[d.status] || ["", d.status])[1])}</span>
        <span class="pill">${d.evidence_count || 0} شاهد</span>
      </div>
    </div>
    ${notes}
    ${d.device_type_source ? `<div class="note info">مبنای تشخیص نوع دستگاه: ${esc(d.device_type_source)}</div>` : ""}

    <details open><summary>جدول اطلاعات دقیق و منبع هر مورد</summary>
      <div class="dbody">
        <table class="factgrid">
          <thead><tr><th>موضوع</th><th>مقدار</th><th>منبع (چطور فهمیدیم)</th><th>اعتبار</th></tr></thead>
          <tbody>${facts}</tbody>
        </table>
      </div>
    </details>

    <details><summary>شواهد زنده‌بودن (${(d.evidence || []).length})</summary>
      <div class="dbody"><ul class="tight">${ev}</ul>
      <div class="src">هر شاهد، یک پاسخ واقعی از خود دستگاه است؛ نه تخمین.</div></div>
    </details>

    ${inf ? `<details open><summary>استنتاج‌های غیرقطعی (جدا از واقعیت‌ها)</summary>
      <div class="dbody"><ul class="tight">${inf}</ul></div></details>` : ""}

    <details open><summary>پورت‌های باز (${(d.open_tcp_ports || []).length})</summary>
      <div class="dbody">${ports}</div>
    </details>

    <details><summary>دادهٔ خام این دستگاه (JSON)</summary>
      <div class="dbody"><pre>${esc(raw)}</pre></div>
    </details>`;
}

/* ------------------------------------------------------------------ utils */
function logLine(msg, level = "") {
  const el = $("log");
  const line = document.createElement("div");
  if (level) line.className = level;
  line.textContent = new Date().toLocaleTimeString("fa-IR") + "  " + msg;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  while (el.childNodes.length > 400) el.removeChild(el.firstChild);
}

function resetUI() {
  STATE.devices.clear();
  STATE.result = null;
  STATE.selected = null;
  STATE.running = false;
  $("rows").innerHTML = "";
  $("log").innerHTML = "";
  $("bar").value = 0;
  $("emptyMsg").style.display = "block";
  $("detail").innerHTML = '<div class="empty">برای مشاهدهٔ جزئیات کامل، روی یک ردیف کلیک کنید.</div>';
  ["jsonBtn", "csvBtn", "htmlBtn"].forEach((b) => { $(b).disabled = true; });
  renderStats();
}

function download(fmt) {
  if (!STATE.scanId) return;
  window.location.href = `/api/export/${STATE.scanId}.${fmt}`;
}

async function updateOui() {
  logLine("در حال دریافت فهرست رسمی IEEE (oui.csv)…");
  const r = await fetch("/api/oui/update", { method: "POST" });
  const d = await r.json();
  logLine(d.ok ? "فهرست IEEE با موفقیت به‌روزرسانی شد." : "به‌روزرسانی ناموفق بود (اتصال اینترنت؟).",
    d.ok ? "" : "warn");
  loadContext();
}

/* ------------------------------------------------------------------ bind */
$("startBtn").addEventListener("click", startScan);
$("stopBtn").addEventListener("click", stopScan);
$("ouiBtn").addEventListener("click", updateOui);
$("jsonBtn").addEventListener("click", () => download("json"));
$("csvBtn").addEventListener("click", () => download("csv"));
$("htmlBtn").addEventListener("click", () => download("html"));
["q", "statusFilter", "typeFilter", "sortBy"].forEach((id) =>
  $(id).addEventListener("input", renderTable));

loadContext();
renderStats();
