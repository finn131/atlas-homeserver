#!/usr/bin/env python3
"""Translate status page from Indonesian to English."""

with open(r"C:\Users\Lenovo\workspace\home-server\atlas-security\status_original.html", "r") as f:
    html = f.read()

# Translation map
translations = {
    "Memuat\u2026": "Loading\u2026",
    "Kembali ke Dashboard": "Back to Dashboard",
    "data diperbarui otomatis tiap 10 detik": "data auto-refreshes every 10 seconds",
    "Sampel": "Samples",
    "Terakhir dicek": "Last checked",
    "Menghubungi backend\u2026": "Connecting to backend\u2026",
    "Semua Sistem Beroperasi Normal": "All Systems Operational",
    "Layanan Bermasalah": "Service(s) Down",
    "Backend tidak terjangkau": "Backend unreachable",
}

for indo, eng in translations.items():
    html = html.replace(indo, eng)

# Fix locale formatting
html = html.replace("'id-ID'", "'en-GB'")

with open(r"C:\Users\Lenovo\workspace\home-server\atlas-security\status_patched.html", "w") as f:
    f.write(html)

print("Status page translated successfully")
