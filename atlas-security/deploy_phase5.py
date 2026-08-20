#!/usr/bin/env python3
"""
Deploy Phase 5 (Security API) to server via paramiko.
Uploads security_api.py, patches backend.py, adds NGINX config, restarts services.
"""
import sys
import base64
import paramiko


HOST = "192.168.1.8"
USER = "nyxx"
SUDO_PASS = "finn"

NGINX_SECURITY_CONF = r"""
# Security API routes — proxied to atlas-backend
location ^~ /api/security/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
""".strip()

# The two lines to add to backend.py, before the @app.websocket line
BACKEND_PYTHON_INJECT = """
# --- Security Observatory API ---
try:
    from security_api import router as _security_router
    app.include_router(_security_router, prefix="/api/security", tags=["security"])
except ImportError:
    import logging
    logging.getLogger("atlas-backend").warning("security_api not found, security endpoints disabled")
"""


def run(cmd, check=True):
    print(f"  >> {cmd}")
    _, stdout, stderr = client.exec_command(f"echo '{SUDO_PASS}' | sudo -S bash -c '{cmd}'", timeout=30)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if check and err and "password:" not in err:
        print(f"     stderr: {err}")
    return out


def upload_file(local_content, remote_path, owner="root:root", mode="0644"):
    encoded = base64.b64encode(local_content.encode()).decode()
    run(f"echo '{encoded}' | base64 -d > {remote_path}")
    run(f"chown {owner} {remote_path} && chmod {mode} {remote_path}")


def upload_security_api():
    print("\n=== Uploading security_api.py ===")
    with open("atlas-security/security_api.py", "r") as f:
        content = f.read()
    upload_file(content, "/opt/atlas/security_api.py", owner="root:root", mode="0644")
    print("  Uploaded /opt/atlas/security_api.py")


def patch_backend_py():
    print("\n=== Patching backend.py ===")

    # Read current backend.py
    _, stdout, _ = client.exec_command(
        f"echo '{SUDO_PASS}' | sudo -S cat /opt/atlas/backend.py", timeout=10
    )
    current = stdout.read().decode()

    if "security_api" in current:
        print("  backend.py already patched, skipping")
        return

    # We need to inject the import+include after the app = FastAPI(...) line
    # Find the line "app = FastAPI(" and add after the closing )
    lines = current.split("\n")
    new_lines = []
    app_found = False
    injected = False

    for i, line in enumerate(lines):
        new_lines.append(line)
        if not app_found and line.strip().startswith("app = FastAPI("):
            app_found = True
            # Find the closing paren of FastAPI() - could be on same or next line
            # Look for the line that ends with )
            continue
        if app_found and not injected:
            # Check if this line closes the FastAPI call
            if ")" in line:
                new_lines.append("")
                new_lines.append("# --- Security Observatory API ---")
                new_lines.append("try:")
                new_lines.append("    from security_api import router as _security_router")
                new_lines.append("    app.include_router(_security_router, prefix=\"/api/security\", tags=[\"security\"])")
                new_lines.append("except ImportError:")
                new_lines.append("    import logging")
                new_lines.append("    logging.getLogger(\"atlas-backend\").warning(\"security_api not found, security endpoints disabled\")")
                injected = True

    if not injected:
        print("  ERROR: Could not find FastAPI() constructor to patch")
        return

    patched = "\n".join(new_lines)

    # Upload patched version
    upload_file(patched, "/opt/atlas/backend.py", owner="root:root", mode="0644")
    print("  Patched /opt/atlas/backend.py")


def add_nginx_route():
    print("\n=== Adding NGINX /api/security/ route ===")

    # Check if route already exists
    _, stdout, _ = client.exec_command(
        f"echo '{SUDO_PASS}' | sudo -S grep -c 'api/security' /etc/nginx/sites-enabled/atlas", timeout=10
    )
    count = stdout.read().decode().strip()
    if count and count != "0":
        print("  Route already exists, skipping")
        return

    # Add the location block before the closing } of the ssl server block
    # We'll add it right after the /api/status location block
    _, stdout, _ = client.exec_command(
        f"echo '{SUDO_PASS}' | sudo -S cat /etc/nginx/sites-enabled/atlas", timeout=10
    )
    nginx_conf = stdout.read().decode()

    # Find the /api/status block and add after it
    marker = "location ^~ /api/status {"
    idx = nginx_conf.find(marker)
    if idx == -1:
        print("  ERROR: Could not find /api/status location block")
        return

    # Find the closing } of this block
    brace_count = 0
    pos = idx
    found_end = False
    while pos < len(nginx_conf):
        if nginx_conf[pos] == "{":
            brace_count += 1
        elif nginx_conf[pos] == "}":
            brace_count -= 1
            if brace_count == 0:
                found_end = True
                break
        pos += 1

    if not found_end:
        print("  ERROR: Could not find closing brace of /api/status block")
        return

    insert_pos = pos + 1
    security_block = """

    location ^~ /api/security/ {
        proxy_pass http://127.0.0.1:8000;

        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
"""
    patched_nginx = nginx_conf[:insert_pos] + security_block + nginx_conf[insert_pos:]

    upload_file(patched_nginx, "/etc/nginx/sites-enabled/atlas", owner="root:root", mode="0644")
    print("  Added /api/security/ location block")


def test_nginx():
    print("\n=== Testing NGINX config ===")
    out = run("nginx -t 2>&1", check=False)
    print(f"  {out}")
    return "test is successful" in out


def restart_services():
    print("\n=== Restarting services ===")
    run("systemctl daemon-reload")
    run("systemctl restart atlas-backend", check=False)
    import time
    time.sleep(2)
    run("systemctl reload nginx", check=False)
    print("  Services restarted")


def test_api():
    print("\n=== Testing API endpoints ===")
    import time
    time.sleep(2)

    endpoints = [
        ("/api/security/status", "Security Status"),
        ("/api/security/events?limit=2", "Events"),
        ("/api/security/detections?limit=2", "Detections"),
        ("/api/security/incidents?limit=2", "Incidents"),
        ("/api/security/alerts?limit=2", "Alerts"),
        ("/api/security/stats?period=24h", "Stats"),
        ("/api/security/security-summary", "Security Summary"),
    ]

    for path, name in endpoints:
        _, stdout, stderr = client.exec_command(
            f"echo '{SUDO_PASS}' | sudo -S curl -sk https://localhost{path} 2>/dev/null",
            timeout=10,
        )
        resp = stdout.read().decode().strip()
        if resp:
            # Check if it's valid JSON
            try:
                import json
                data = json.loads(resp)
                print(f"  {name}: OK ({len(resp)} bytes)")
            except:
                print(f"  {name}: ERROR - {resp[:100]}")
        else:
            err = stderr.read().decode().strip()
            print(f"  {name}: EMPTY - {err[:100]}")

    # Test existing endpoint still works
    _, stdout, _ = client.exec_command(
        f"echo '{SUDO_PASS}' | sudo -S curl -sk https://localhost/api/status 2>/dev/null",
        timeout=10,
    )
    resp = stdout.read().decode().strip()
    if resp:
        print(f"  /api/status (existing): OK")
    else:
        print(f"  /api/status (existing): FAILED")


if __name__ == "__main__":
    global client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, look_for_keys=False)

    try:
        upload_security_api()
        patch_backend_py()
        add_nginx_route()
        if test_nginx():
            restart_services()
            test_api()
        else:
            print("\nERROR: NGINX config test failed, not restarting")
    finally:
        client.close()
