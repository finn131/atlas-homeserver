#!/bin/bash
# Import security dashboard into Grafana via API
DASHBOARD=$(cat /etc/atlas/grafana/provisioning/dashboards/security.json)
PAYLOAD=$(python3 -c "
import json, sys
dashboard = json.loads('''$DASHBOARD''')
# Remove top-level fields that don't belong in the dashboard body
for k in ['id', 'version']:
    dashboard.pop(k, None)
print(json.dumps({'dashboard': dashboard, 'folderId': 0, 'overwrite': True}))
" 2>/dev/null)

if [ -z "$PAYLOAD" ]; then
  echo "Failed to create payload"
  exit 1
fi

curl -s -X POST -u admin:finn -H 'Content-Type: application/json' \
  -d "$PAYLOAD" http://127.0.0.1:3000/api/dashboards/db
