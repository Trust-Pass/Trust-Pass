# Local tools image for scripts/backup/trustpass-backup-drill.sh
# postgres:18 (Debian trixie) drops its CA bundle after build; add it back (needed for TLS
# verify-full), plus 7-Zip and Node.js (for verify-secrets.mjs, built-in crypto only). On trixie, /usr/bin/7zz comes from 7zip-standalone (the 7zip
# package only ships 7z/7za/7zr). The build fails if 7zz or the CA bundle is missing.
#   PowerShell: Get-Content scripts/backup/Dockerfile -Raw | docker build --no-cache -t trustpass-pgtools:18 -
#   bash:       docker build --no-cache -t trustpass-pgtools:18 - < scripts/backup/Dockerfile
FROM postgres:18
LABEL trustpass.tools="pg18-ca-7zz-node-v3"
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates 7zip-standalone nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && command -v 7zz && node --version \
 && test "$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt)" -gt 50
