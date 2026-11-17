# Local tools image for scripts/backup/trustpass-backup-drill.sh
# postgres:18 drops its CA bundle after build; add it back (needed for TLS verify-full) plus 7-Zip.
#   PowerShell: Get-Content scripts/backup/Dockerfile -Raw | docker build -t trustpass-pgtools:18 -
#   bash:       docker build -t trustpass-pgtools:18 - < scripts/backup/Dockerfile
FROM postgres:18
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates 7zip \
 && rm -rf /var/lib/apt/lists/*
