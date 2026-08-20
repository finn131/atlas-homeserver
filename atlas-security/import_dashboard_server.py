import json
import urllib.request
import urllib.error
import base64

# Read the dashboard JSON
with open("/etc/atlas/grafana/provisioning/dashboards/security.json", "r") as f:
    dashboard = json.load(f)

# Remove top-level fields that don't belong in the dashboard body
for k in ["id", "version"]:
    dashboard.pop(k, None)

# Create the payload
payload = json.dumps({
    "dashboard": dashboard,
    "folderId": 0,
    "overwrite": True
}).encode("utf-8")

# Create the request
url = "http://127.0.0.1:3000/api/dashboards/db"
credentials = base64.b64encode(b"admin:finn").decode("utf-8")

req = urllib.request.Request(
    url,
    data=payload,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}"
    },
    method="POST"
)

try:
    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode("utf-8"))
        print("Success:", json.dumps(result, indent=2))
except urllib.error.HTTPError as e:
    print(f"HTTP Error {e.code}: {e.reason}")
    print(e.read().decode("utf-8"))
except Exception as e:
    print(f"Error: {e}")
