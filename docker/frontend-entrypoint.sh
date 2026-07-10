#!/bin/sh
# Generates the SPA's runtime config from environment variables at container
# start, so a single frontend image serves any environment without a rebuild.
# Placed in /docker-entrypoint.d/, it runs before the official nginx entrypoint
# starts the server.
set -e

cat > /usr/share/nginx/html/config.js <<EOF
window.__CONFIG__ = {
  authMode: "${AUTH_MODE:-localdev}",
  oidcAuthority: "${OIDC_AUTHORITY:-}",
  oidcClientId: "${OIDC_CLIENT_ID:-}",
  oidcScope: "${OIDC_SCOPE:-openid profile}",
  apiBase: "${API_BASE:-}"
};
EOF

echo "frontend: wrote /config.js (authMode=${AUTH_MODE:-localdev})"
