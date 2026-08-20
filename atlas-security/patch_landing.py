#!/usr/bin/env python3
"""Patch landing page to add Security Status card."""

with open(r"C:\Users\Lenovo\workspace\home-server\atlas-security\index_original.html", "r") as f:
    html = f.read()

# 1. Add SECURITY CSS section before FOOTER section
security_css = """
/* ============ SECURITY ============ */
.sec-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.sec-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:10px 12px;text-align:center}
.sec-box .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.sec-box .n{font-size:18px;font-weight:800;margin-top:4px;font-variant-numeric:tabular-nums}
.sec-box.high .n{color:var(--danger)}
.sec-box.med .n{color:var(--warning)}
.sec-box.low .n{color:var(--primary)}
.sec-box.info .n{color:var(--muted)}
.sec-detections{margin-top:12px}
.sec-det{display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px dashed var(--border);font-size:12px}
.sec-det:last-child{border-bottom:none}
.sec-det .t{color:var(--muted);font-variant-numeric:tabular-nums;min-width:40px}
.sec-det .r{font-weight:600}
.sec-det .r.high{color:var(--danger)}
.sec-det .r.medium{color:var(--warning)}
.sec-det .r.low{color:var(--primary)}
.sec-det .ip{color:var(--muted);margin-left:auto}
.sec-link{display:inline-block;margin-top:12px;color:var(--primary);text-decoration:none;font-size:13px;font-weight:600;letter-spacing:.5px}
.sec-link:hover{text-decoration:underline}
"""

html = html.replace("/* ============ FOOTER ============ */", security_css + "/* ============ FOOTER ============ */")

# 2. Add Security card HTML after the Network card (card #6), before Live Charts
security_card = """
    <div class="card">
      <h3><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Security Status</h3>
      <div id="secBadge" style="margin-bottom:10px"></div>
      <div class="sec-row">
        <div class="sec-box high"><div class="lbl">High</div><div class="n" id="secHigh">-</div></div>
        <div class="sec-box med"><div class="lbl">Medium</div><div class="n" id="secMed">-</div></div>
        <div class="sec-box low"><div class="lbl">Low</div><div class="n" id="secLow">-</div></div>
        <div class="sec-box info"><div class="lbl">Events</div><div class="n" id="secEvents">-</div></div>
      </div>
      <div class="sec-detections" id="secDetections"></div>
      <a class="sec-link" href="/grafana/d/atlas-security/atlas-security" target="_blank">Open Security Dashboard &rarr;</a>
    </div>

"""

# Insert after the Network card closing div (the one with net-active)
html = html.replace(
    """      <div style="margin-top:12px;font-size:12px;color:var(--muted)" id="netActive">Network Active</div>
    </div>

    <div class="card chart-card">""",
    """      <div style="margin-top:12px;font-size:12px;color:var(--muted)" id="netActive">Network Active</div>
    </div>
""" + security_card + """
    <div class="card chart-card">"""
)

# 3. Add security rendering function and call it from render()
security_js = """
function renderSecurity(sec) {
  if (!sec) return;
  const badge = document.getElementById('secBadge');
  const colorMap = {ok: 'var(--success)', warning: 'var(--warning)', critical: 'var(--danger)', unknown: 'var(--muted)'};
  const labelMap = {ok: 'SECURE', warning: 'WARNING', critical: 'CRITICAL', unknown: 'UNKNOWN'};
  badge.innerHTML = '<span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:' + (colorMap[sec.status]||'var(--muted)') + ';background:' + (colorMap[sec.status]||'var(--muted)') + '18;border:1px solid ' + (colorMap[sec.status]||'var(--muted)') + '66"><span class="dot" style="background:' + (colorMap[sec.status]||'var(--muted)') + '"></span>' + (labelMap[sec.status]||'UNKNOWN') + ' &middot; ' + sec.active_alerts + ' alert(s)</span>';
  document.getElementById('secHigh').textContent = sec.high_severity || 0;
  document.getElementById('secMed').textContent = sec.medium_severity || 0;
  document.getElementById('secLow').textContent = sec.low_severity || 0;
  document.getElementById('secEvents').textContent = sec.events_today || 0;
  const detList = document.getElementById('secDetections');
  if (sec.recent_detections && sec.recent_detections.length > 0) {
    detList.innerHTML = sec.recent_detections.map(d =>
      '<div class="sec-det"><span class="t">' + esc(d.time) + '</span><span class="r ' + esc(d.severity) + '">' + esc(d.rule) + '</span><span class="ip">' + esc(d.src_ip) + '</span></div>'
    ).join('');
  } else {
    detList.innerHTML = '<div style="font-size:12px;color:var(--muted);padding:6px 4px">No recent detections</div>';
  }
}
"""

# Add esc function if not present (it's not in the current code)
esc_func = """
function esc(s){
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}
"""

# Insert esc function and renderSecurity before the sparkline calls
html = html.replace(
    "sparkline('chartCpu',",
    security_js + esc_func + "\nsparkline('chartCpu',"
)

# 4. Add renderSecurity call inside the render function
html = html.replace(
    "  // services\n  renderServices(data.services);",
    "  // security\n  renderSecurity(data.security);\n\n  // services\n  renderServices(data.services);"
)

# Add responsive rule for security card
html = html.replace(
    "@media(max-width:992px){\n  .grid{grid-template-columns:repeat(2,1fr)}",
    "@media(max-width:992px){\n  .grid{grid-template-columns:repeat(2,1fr)}\n  .sec-row{grid-template-columns:repeat(2,1fr)}"
)

# Also fix the responsive rule for small screens
html = html.replace(
    "@media(max-width:640px){\n  .grid,.charts,.qa-grid,.service-list{grid-template-columns:1fr}",
    "@media(max-width:640px){\n  .grid,.charts,.qa-grid,.service-list,.sec-row{grid-template-columns:1fr}"
)

with open(r"C:\Users\Lenovo\workspace\home-server\atlas-security\index_patched.html", "w") as f:
    f.write(html)

print("Landing page patched successfully")
