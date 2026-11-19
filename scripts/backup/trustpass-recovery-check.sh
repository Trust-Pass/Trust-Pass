#!/bin/bash
# TrustPass: document recovery check on an EXISTING encrypted backup
# ------------------------------------------------------------------
# Proves that an existing backup (.7z) plus the secrets saved in your password manager are
# enough to recover every document: it decrypts the backup, restores it into a throw-away
# PostgreSQL in RAM, then decrypts every document key, file, field, credential and share-link
# copy with your saved MASTER_KEY, and checks the issuer key with your saved ISSUER_SIGNING_SEED.
#
#   docker run --rm -it --network none --tmpfs /work:rw,size=512m,mode=0711 \
#     -v "${PWD}:/backup:ro" -v "${PWD}/recovery-reports:/out" \
#     trustpass-pgtools:18 bash /backup/trustpass-recovery-check.sh [archive.7z]
#
# Safety:
#  - No network at all (--network none; checked below). It never connects to production.
#  - The backup folder is mounted READ-ONLY: existing backups cannot be changed or deleted.
#  - Everything decrypted (database dump, files, fields) exists only in RAM (/work, tmpfs) and
#    disappears when the container ends. Decrypted files are checked in memory, never saved.
#  - Secrets and the passphrase are typed at hidden prompts, passed to 7-Zip and Node through
#    pipes (not command lines or environment variables), never printed, logged or saved.
#  - The only file written is a report in recovery-reports/: counts, short document ids, sizes,
#    file types, yes/no answers. No secret, title, field value or document content.
# No new backup is made and no key is created, changed or rotated.
set -euo pipefail
umask 077

WORK="/work"
IN="/backup"
OUT="/out"
SELFTEST="${TRUSTPASS_RECOVERY_SELFTEST:-0}"   # only used by the developer test harness

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m  %s\n' "$*"; }
fail() { printf '\n  \033[31mSTOPPED:\033[0m %s\n\n' "$*" >&2; exit 1; }

# Hidden prompt; keys typed ahead (e.g. the extra line break of a paste) are discarded first.
read_secret() {
  local _junk
  while IFS= read -r -s -t 0.3 -n 4096 _junk 2>/dev/null; do :; done
  IFS= read -r -s -p "$1" REPLY_SECRET || REPLY_SECRET=""
  echo
  REPLY_SECRET="${REPLY_SECRET%$'\r'}"
}

cleanup() {
  if [ -f "$WORK/pg/data/postmaster.pid" ]; then
    gosu postgres pg_ctl -D "$WORK/pg/data" -m fast -w stop >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- 0. pre-flight
say "[0/5] Checks before starting"
if [ "$SELFTEST" != 1 ]; then
  grep -qE "^[^ ]+ $WORK tmpfs " /proc/mounts || fail "$WORK is not a RAM disk. Start the container with --tmpfs /work:rw,size=512m,mode=0711"
  [ -z "$(ls -A "$WORK")" ] || fail "$WORK is not empty; start a new container"
  nets=$(ls /sys/class/net | grep -v '^lo$' || true)
  [ -z "$nets" ] || fail "this container has network access ($nets). Start it with --network none"
  touch "$IN/.write-test" 2>/dev/null && { rm -f "$IN/.write-test"; fail "the backup folder is writable. Mount it read-only: -v \"\${PWD}:/backup:ro\""; }
fi
ok "RAM only, no network, backup folder read-only"
[ -d "$OUT" ] && [ -w "$OUT" ] || fail "$OUT is not mounted. Add: -v \"\${PWD}/recovery-reports:/out\""
for tool in 7zz node pg_restore initdb psql; do command -v "$tool" >/dev/null || fail "$tool is missing. Rebuild trustpass-pgtools:18 from scripts/backup/Dockerfile"; done
[ -f "$IN/verify-secrets.mjs" ] || fail "verify-secrets.mjs is not in the backup folder"
ok "$(pg_restore --version), $(node --version), 7-Zip present"

# ---------------------------------------------------------------- 1. pick and verify the archive
say "[1/5] Find the backup and check it is intact"
if [ $# -ge 1 ]; then
  ARCHIVE="$IN/$(basename "$1")"
else
  ARCHIVE=$(ls -1 "$IN"/trustpass-*.7z 2>/dev/null | while read -r f; do [ -f "$f.sha256" ] && [ -f "${f%.7z}-report.txt" ] && echo "$f"; done | sort | tail -1 || true)
fi
[ -n "$ARCHIVE" ] && [ -f "$ARCHIVE" ] || fail "no backup found (needs trustpass-*.7z with its .sha256 and -report.txt)"
NAME=$(basename "$ARCHIVE" .7z)
[ -f "$ARCHIVE.sha256" ] || fail "$NAME.7z.sha256 is missing"
( cd "$IN" && sha256sum -c --quiet "$NAME.7z.sha256" ) || fail "$NAME.7z does not match its SHA-256: the file is damaged or was changed"
ok "$NAME.7z, SHA-256 matches"

# ---------------------------------------------------------------- 2. decrypt the backup into RAM
say "[2/5] Decrypt the backup (into RAM)"
echo "  Paste the BACKUP PASSPHRASE from your password manager. Nothing is shown while typing."
read_secret "  Backup passphrase: "
PASS="$REPLY_SECRET"
unset REPLY_SECRET
mkdir -p "$WORK/dump"
# 7-Zip reads the passphrase from the pipe (for extraction, a bare -p would mean an EMPTY one).
if ! printf '%s\n' "$PASS" | 7zz x -y -bso0 -bsp0 -o"$WORK/dump" "$ARCHIVE" >/dev/null 2>&1; then
  unset PASS
  fail "the backup could not be decrypted: wrong passphrase, or damaged archive"
fi
unset PASS
DUMP=$(ls -1 "$WORK/dump"/*.dump 2>/dev/null | head -1 || true)
[ -n "$DUMP" ] || fail "the archive contains no .dump file"
pg_restore --list "$DUMP" > /dev/null || fail "the decrypted dump is not readable"
ok "decrypted $(basename "$DUMP") ($(stat -c %s "$DUMP") bytes) into RAM"

# ---------------------------------------------------------------- 3. restore into RAM PostgreSQL
say "[3/5] Restore into a temporary PostgreSQL (RAM only, local socket, no network)"
mkdir -p "$WORK/pg"
chown postgres:postgres "$WORK/pg"
gosu postgres mkdir -p "$WORK/pg/data" "$WORK/pg/sock"
gosu postgres initdb -D "$WORK/pg/data" -U postgres -A trust --no-sync >/dev/null
gosu postgres pg_ctl -D "$WORK/pg/data" -l "$WORK/pg/log" -w \
  -o "-c listen_addresses='' -c unix_socket_directories=$WORK/pg/sock -c fsync=off" start >/dev/null
L=(-h "$WORK/pg/sock" -U postgres)
createdb "${L[@]}" recovery_check
pg_restore "${L[@]}" --dbname=recovery_check --no-owner --no-privileges --exit-on-error "$DUMP" || fail "pg_restore failed"
rm -f "$DUMP"
q() { psql "${L[@]}" -d recovery_check -XAtq -v ON_ERROR_STOP=1 -c "$1"; }
ok "restored: $(q "select count(*) from pg_tables where schemaname='public'") tables, $(q "select count(*) from documents where deleted_at is null") active documents"

# Everything the checker needs, as JSON in RAM. Plain titles and labels (older rows) are left out:
# the checker never needs them.
q "SELECT json_build_object(
  'documents', COALESCE((SELECT json_agg((to_jsonb(d) - 'title') || jsonb_build_object('file', encode(so.data, 'hex'), 'key', to_jsonb(k)))
                         FROM documents d LEFT JOIN document_keys k ON k.document_id = d.id
                         LEFT JOIN stored_objects so ON so.key = d.storage_key), '[]'::json),
  'claims', COALESCE((SELECT json_agg(to_jsonb(c) - 'label') FROM document_claims c), '[]'::json),
  'credentials', COALESCE((SELECT json_agg(json_build_object('document_id', document_id, 'document_hash', document_hash,
                                                            'credential_encrypted', encode(credential_encrypted, 'hex'))) FROM credentials), '[]'::json),
  'links', COALESCE((SELECT json_agg(json_build_object('id', id, 'token_hash', token_hash, 'token_encrypted', encode(token_encrypted, 'hex')))
                     FROM sharing_links), '[]'::json),
  'issuers', COALESCE((SELECT json_agg(public_key_jwk) FROM issuers), '[]'::json),
  'kmsKeys', CASE WHEN to_regclass('key_encryption_keys') IS NULL THEN 0 ELSE 1 END)" > "$WORK/export.json"

# ---------------------------------------------------------------- 4. decrypt every document
say "[4/5] Recover every document with your saved keys"
echo "  Paste each value from your password manager. Nothing is shown, logged or saved."
read_secret "  MASTER_KEY: "; MK="$REPLY_SECRET"
read_secret "  ISSUER_SIGNING_SEED: "; IS="$REPLY_SECRET"
unset REPLY_SECRET
[ -n "$MK" ] || fail "MASTER_KEY is empty"
set +e
printf '%s\n%s\n' "$MK" "$IS" | node "$IN/verify-secrets.mjs" "$WORK/export.json" > "$WORK/result.json"
code=$?
set -e
unset MK IS
rm -f "$WORK/export.json"

# ---------------------------------------------------------------- 5. report
say "[5/5] Result"
REPORT="$OUT/$NAME-recovery-$(date -u +%Y-%m-%dT%H%MZ).txt"
{
  echo "TrustPass document recovery check"
  echo "Backup:      $NAME.7z (SHA-256 $(cut -d' ' -f1 "$IN/$NAME.7z.sha256"))"
  echo "Checked at:  $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
  echo "Environment: no network, RAM only, backup folder read-only, PostgreSQL $(q 'show server_version' | cut -d' ' -f1)"
  echo
  cat "$WORK/result.json"
  echo
  if [ "$code" = 0 ]; then echo "RESULT: RECOVERY OK"; else echo "RESULT: RECOVERY FAILED (see failures above)"; fi
} > "$REPORT"
sed 's/^/  /' "$WORK/result.json"
echo
if [ "$code" = 0 ]; then
  ok "RECOVERY OK: every document, field and credential decrypted with your saved keys"
else
  printf '  \033[31mRECOVERY FAILED\033[0m: see "failures" and "verdict" above\n'
fi
ok "report: recovery-reports/$(basename "$REPORT") (no secrets, no document content)"
ok "all decrypted data was only in RAM and disappears when this container closes"
echo
exit "$code"
