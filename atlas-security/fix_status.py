#!/usr/bin/env python3
with open('/var/www/atlas/status/index.html', 'r') as f:
    html = f.read()
html = html.replace('Memuat&hellip;', 'Loading&hellip;')
html = html.replace('Semua Sistem Beroperasi Normal', 'All Systems Operational')
html = html.replace('Layanan Bermasalah', 'Service(s) Down')
html = html.replace('Backend tidak terjangkau', 'Backend unreachable')
html = html.replace('Sampel', 'Samples')
html = html.replace('Terakhir dicek', 'Last checked')
html = html.replace('Menghubungi backend&hellip;', 'Connecting to backend&hellip;')
html = html.replace("'id-ID'", "'en-GB'")
with open('/var/www/atlas/status/index.html', 'w') as f:
    f.write(html)
print('Status page translated')
