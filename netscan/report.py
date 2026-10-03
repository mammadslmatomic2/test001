"""
report.py — تولید گزارش HTML مستقل (خودبسنده) از نتیجهٔ اسکن.

خروجی یک فایل واحد HTML است که بدون سرور و بدون اینترنت باز می‌شود و همهٔ
اطلاعات (واقعیت‌ها + منبع هر واقعیت) را نمایش می‌دهد.
"""

from __future__ import annotations

import html
import json
from typing import Any


def _esc(x: Any) -> str:
    return html.escape(str(x if x is not None else ""))


def render_html_report(result: dict[str, Any], title: str = "گزارش اسکن شبکه") -> str:
    # جلوگیری از شکستن تگ <script> توسط دادهٔ حاوی «</script>»
    data_json = (json.dumps(result, ensure_ascii=False)
                 .replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    scan = result.get("scan", {})
    summary = result.get("summary", {})
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
:root {{
  --bg: #0b1020; --panel: #131a2e; --panel2: #182142; --line: #263052;
  --txt: #e8ecf7; --muted: #9aa6c4; --acc: #4f8cff; --ok: #2ecc71; --warn: #f39c12;
  --bad: #e74c3c; --chip: #22305a;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--txt);
  font-family: "Vazirmatn", "IRANSans", Tahoma, "Segoe UI", sans-serif; line-height: 1.7; }}
a {{ color: var(--acc); }}
header {{ padding: 26px 22px; background: linear-gradient(135deg,#152046,#0e152b); }}
.wrap {{ max-width: 1400px; margin: 0 auto; padding: 0 18px 60px; }}
h1 {{ margin: 0 0 6px; font-size: 26px; }}
.sub {{ color: var(--muted); font-size: 14px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(170px,1fr)); gap: 12px; margin: 18px 0; }}
.card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; }}
.card .k {{ color: var(--muted); font-size: 12px; }}
.card .v {{ font-size: 22px; font-weight: 700; margin-top: 4px; }}
table {{ width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }}
th, td {{ padding: 10px 12px; text-align: right; border-bottom: 1px solid var(--line); font-size: 13.5px; vertical-align: top; }}
th {{ background: var(--panel2); font-size: 12.5px; color: var(--muted); font-weight: 600; }}
tr:hover td {{ background: #17203c; }}
.chip {{ display: inline-block; background: var(--chip); border: 1px solid var(--line); border-radius: 999px;
  padding: 1px 9px; margin: 1px 2px; font-size: 12px; direction: ltr; }}
.badge {{ display: inline-block; border-radius: 8px; padding: 1px 8px; font-size: 12px; border: 1px solid var(--line); }}
.b-ok {{ background: rgba(46,204,113,.15); color: #7ff0b0; }}
.b-warn {{ background: rgba(243,156,18,.15); color: #ffd18a; }}
.b-bad {{ background: rgba(231,76,60,.15); color: #ff9b90; }}
.b-info {{ background: rgba(79,140,255,.15); color: #a9c7ff; }}
details {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; margin: 12px 0; }}
details > summary {{ cursor: pointer; padding: 12px 16px; font-weight: 700; }}
details .body {{ padding: 0 16px 16px; }}
.facts td {{ font-size: 13px; }}
.src {{ color: var(--muted); font-size: 12px; }}
.note {{ background: rgba(243,156,18,.09); border: 1px solid rgba(243,156,18,.35);
  border-radius: 12px; padding: 10px 14px; margin: 10px 0; font-size: 13.5px; }}
.legend {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; color: var(--muted); font-size: 12.5px; }}
pre {{ background: #0a0f1f; border: 1px solid var(--line); border-radius: 12px; padding: 12px; overflow: auto;
  direction: ltr; text-align: left; font-size: 12px; }}
@media print {{ body {{ background: #fff; color: #000; }} table, .card, details {{ border-color: #ccc; }} }}
</style>
</head>
<body>
<header><div class="wrap" style="padding:0">
  <h1>{_esc(title)}</h1>
  <div class="sub">گرفته‌شده در {_esc(scan.get('target'))} | رابط: {_esc(scan.get('interface'))} |
  آدرس محلی: {_esc(scan.get('local_ip'))} | دروازه: {_esc(scan.get('gateway'))} |
  مدت: {_esc(scan.get('duration_sec'))} ثانیه</div>
</div></header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="k">دستگاه‌های شناسایی‌شده</div><div class="v">{summary.get('devices_online', 0)}</div></div>
    <div class="card"><div class="k">دارای MAC</div><div class="v">{summary.get('with_mac', 0)}</div></div>
    <div class="card"><div class="k">دارای نام میزبان</div><div class="v">{summary.get('with_hostname', 0)}</div></div>
    <div class="card"><div class="k">مجموع پورت‌های باز</div><div class="v">{summary.get('open_ports_total', 0)}</div></div>
    <div class="card"><div class="k">آدرس‌های بررسی‌شده</div><div class="v">{scan.get('hosts_scanned', 0)}</div></div>
  </div>

  {''.join(f'<div class="note">⚠️ {_esc(w)}</div>' for w in result.get('warnings', []))}

  <div class="legend" style="margin:14px 0">
    <b>راهنمای دقت:</b>
    <span class="badge b-ok">قطعی</span> خوانده‌شده از خود دستگاه (پاسخ واقعی پروتکل)
    <span class="badge b-info">ثبت‌شده</span> از پایگاه رسمی/IEEE یا فایل سیستم
    <span class="badge b-warn">استنتاجی</span> برداشت غیرقطعی — با ذکر دلیل، جداگانه نمایش داده می‌شود
  </div>

  <table>
    <thead><tr>
      <th>#</th><th>آدرس IP</th><th>نام</th><th>MAC</th><th>سازندهٔ کارت شبکه</th>
      <th>نوع دستگاه</th><th>پورت‌های باز</th><th>تعداد شواهد</th>
    </tr></thead>
    <tbody id="rows"></tbody>
  </table>

  <div id="details"></div>

  <h2 style="margin-top:26px">دادهٔ خام (JSON)</h2>
  <details><summary>نمایش کامل JSON</summary><div class="body"><pre id="raw"></pre></div></details>
</div>
<script>
const DATA = {data_json};
const esc = s => (s===null||s===undefined) ? '' : String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const rows = document.getElementById('rows');
const details = document.getElementById('details');
const STATUS = {{online:['b-ok','آنلاین'], dhcp_only:['b-warn','شناسایی از DHCP'], unknown:['b-info','نامعلوم']}};

DATA.devices.forEach((d,i) => {{
  const [cls,label] = STATUS[d.status] || ['b-info', d.status];
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${{i+1}}</td>
    <td><b dir="ltr">${{esc(d.ip)}}</b> ${{d.is_gateway?'<span class="badge b-info">دروازه</span>':''}} ${{d.is_self?'<span class="badge b-info">همین دستگاه</span>':''}}</td>
    <td>${{esc(d.name) || '<span class="src">—</span>'}}</td>
    <td dir="ltr">${{esc(d.mac) || '<span class="src">در دسترس نیست</span>'}}</td>
    <td>${{esc(d.mac_vendor) || '<span class="src">نامشخص</span>'}} ${{d.mac_is_random?'<span class="badge b-warn">MAC تصادفی</span>':''}}</td>
    <td>${{esc(d.device_type) || '<span class="src">نامشخص</span>'}}
        ${{d.device_type && !d.device_type_certain ? '<span class="badge b-warn">استنتاجی</span>' : (d.device_type ? '<span class="badge b-ok">مبتنی بر شاهد</span>' : '')}}</td>
    <td>${{(d.open_tcp_ports||[]).slice(0,12).map(p=>`<span class="chip">${{p.port}}${{p.service?' · '+esc(p.service):''}}</span>`).join(' ')}}
        ${{(d.open_tcp_ports||[]).length>12?`<span class="src"> و ${{d.open_tcp_ports.length-12}} پورت دیگر</span>`:''}}</td>
    <td>${{d.evidence_count}} <span class="badge ${{cls}}">${{label}}</span></td>`;
  rows.appendChild(tr);

  const facts = (d.facts||[]).map(f => `<tr>
      <td>${{esc(f.key)}}</td><td>${{esc(f.value)}}</td>
      <td class="src">${{esc(f.source)}}</td>
      <td>${{f.certain ? '<span class="badge b-ok">قطعی</span>' : '<span class="badge b-warn">غیرقطعی/استنتاجی</span>'}}</td></tr>`).join('');
  const ev = (d.evidence||[]).map(e => `<li>${{esc(e.detail)}}</li>`).join('');
  const inf = (d.inferences||[]).map(x => `<li><b>${{esc(x.claim)}}</b> — <span class="src">دلیل: ${{esc(x.basis)}}</span></li>`).join('');
  const notes = (d.notes||[]).map(n => `<div class="note">ℹ️ ${{esc(n)}}</div>`).join('');
  const det = document.createElement('details');
  det.innerHTML = `<summary>دستگاه <span dir="ltr">${{esc(d.ip)}}</span>${{d.name?' — '+esc(d.name):''}} — ${{esc(d.device_type||'نوع نامشخص')}} (${{d.evidence_count}} شاهد)</summary>
    <div class="body">
      ${{notes}}
      <h4>شواهد زنده‌بودن</h4><ul>${{ev || '<li class="src">—</li>'}}</ul>
      ${{inf ? `<h4>استنتاج‌های غیرقطعی (جدا از واقعیت‌ها)</h4><ul>${{inf}}</ul>` : ''}}
      <h4>جدول اطلاعات و منبع هر مورد</h4>
      <table class="facts"><thead><tr><th>موضوع</th><th>مقدار</th><th>منبع</th><th>اعتبار</th></tr></thead>
      <tbody>${{facts || '<tr><td colspan="4" class="src">اطلاعات تکمیلی‌ای ثبت نشد</td></tr>'}}</tbody></table>
      <h4>دادهٔ خام این دستگاه</h4>
      <pre>${{esc(JSON.stringify(d.raw, null, 2))}}</pre>
    </div>`;
  details.appendChild(det);
}});
document.getElementById('raw').textContent = JSON.stringify(DATA, null, 2);
</script>
</body>
</html>
"""
