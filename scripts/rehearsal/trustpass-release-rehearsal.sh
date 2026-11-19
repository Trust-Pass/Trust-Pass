#!/bin/bash
# TrustPass: release rehearsal on a COPY of the production backup
# ----------------------------------------------------------------
# Runs exactly what the release will do to production (the database migrations, the start-up key
# checks and the metadata backfill), but on a throw-away restore of an existing encrypted backup,
# and proves that every document, field, credential, share link and recipient download still
# works afterwards.
#
#   docker run --rm -it --network none --tmpfs /work:rw,size=1g,mode=0711 \
#     -v "${PWD}:/backup:ro" -v "${PWD}/rehearsal-reports:/out" \
#     trustpass-rehearsal:release [archive.7z]
#
# Safety:
#  - No network at all (--network none; checked below). It never connects to production: the
#    application only accepts a local-socket database and refuses any remote host.
#  - The backup folder is mounted READ-ONLY: existing backups cannot be changed or deleted.
#  - The restored database, every decrypted file and every converted row exist only in RAM
#    (/work, tmpfs) and disappear when the container ends.
#  - Secrets and the passphrase are typed at hidden prompts and passed through pipes (not command
#    lines or environment variables); they are never printed, logged or saved.
#  - The only file written is a report in rehearsal-reports/: counts, short ids, yes/no answers.
#    No secret, title, name, field value, link or document content.
# Nothing in production is read or changed; no key is created, changed or rotated.
set -euo pipefail
umask 077

WORK="/work"
IN="/backup"
OUT="/out"
API="/app/apps/api"
SELFTEST="${TRUSTPASS_REHEARSAL_SELFTEST:-0}"   # only used by the CI test of this script

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m  %s\n' "$*"; }
fail() { printf '\n  \033[31mSTOPPED:\033[0m %s\n\n' "$*" >&2; exit 1; }

# Hidden prompt; keys typed ahead (e.g. the extra line break of a paste) are discarded first.
read_secret() {
  local _junk
  if [ "$SELFTEST" != 1 ]; then
    while IFS= read -r -s -t 0.3 -n 4096 _junk 2>/dev/null; do :; done
  fi
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
say "[0/7] Checks before starting"
grep -qE "^[^ ]+ $WORK tmpfs " /proc/mounts || fail "$WORK is not a RAM disk. Start the container with --tmpfs /work:rw,size=1g,mode=0711"
[ -z "$(ls -A "$WORK")" ] || fail "$WORK is not empty; start a new container"
nets=$(ls /sys/class/net | grep -v '^lo$' || true)
[ -z "$nets" ] || fail "this container has network access ($nets). Start it with --network none"
touch "$IN/.write-test" 2>/dev/null && { rm -f "$IN/.write-test"; fail "the backup folder is writable. Mount it read-only: -v \"\${PWD}:/backup:ro\""; }
ok "RAM only, no network, backup folder read-only"
[ -d "$OUT" ] && [ -w "$OUT" ] || fail "$OUT is not mounted. Add: -v \"\${PWD}/rehearsal-reports:/out\""
for tool in 7zz node pg_restore initdb psql; do command -v "$tool" >/dev/null || fail "$tool is missing. Rebuild trustpass-rehearsal:release"; done
[ -f "$API/dist/rehearsal.js" ] && [ -x "$API/node_modules/.bin/prisma" ] || fail "the release build is missing from the image. Rebuild trustpass-rehearsal:release"
RELEASE=$(cat /app/RELEASE 2>/dev/null || echo unknown)
ok "release build $RELEASE, $(pg_restore --version), node $(node --version), 7-Zip present"

# ---------------------------------------------------------------- 1. pick and verify the archive
say "[1/7] Find the backup and check it is intact"
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
say "[2/7] Decrypt the backup (into RAM)"
echo "  Paste the BACKUP PASSPHRASE from your password manager. Nothing is shown while typing."
read_secret "  Backup passphrase: "
PASS="$REPLY_SECRET"
unset REPLY_SECRET
mkdir -p "$WORK/dump"
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
say "[3/7] Restore into a temporary PostgreSQL (RAM only, local socket, no network)"
mkdir -p "$WORK/pg"
chown postgres:postgres "$WORK/pg"
gosu postgres mkdir -p "$WORK/pg/data" "$WORK/pg/sock"
gosu postgres initdb -D "$WORK/pg/data" -U postgres -A trust --no-sync >/dev/null
gosu postgres pg_ctl -D "$WORK/pg/data" -l "$WORK/pg/log" -w \
  -o "-c listen_addresses='' -c unix_socket_directories=$WORK/pg/sock -c fsync=off" start >/dev/null
L=(-h "$WORK/pg/sock" -U postgres)
DB=rehearsal
createdb "${L[@]}" "$DB"
pg_restore "${L[@]}" --dbname="$DB" --no-owner --no-privileges --exit-on-error "$DUMP" || fail "pg_restore failed"
rm -f "$DUMP"
q() { psql "${L[@]}" -d "$DB" -XAtq -v ON_ERROR_STOP=1 -c "$1"; }
ok "restored: $(q "select count(*) from pg_tables where schemaname='public'") tables, $(q "select count(*) from documents where deleted_at is null") active documents, $(q "select count(*) from sharing_links") share links"
APPLIED_BEFORE=$(q "select count(*) from _prisma_migrations where finished_at is not null")
ok "migrations already applied in the backup: $APPLIED_BEFORE"

# ---------------------------------------------------------------- 4. fingerprint the existing data
say "[4/7] Fingerprint every existing table and column (before the release migrations)"
# One md5 per table over every row of the columns that exist today. The same query (same columns)
# runs again after the migrations: identical answers mean no existing value was removed or changed.
q "SELECT string_agg(format(
     'SELECT %L AS t, count(*) AS n, md5(coalesce(string_agg(md5(ROW(%s)::text), '','' ORDER BY md5(ROW(%s)::text)), '''')) AS h FROM %I',
     table_name, cols, cols, table_name), ' UNION ALL ' ORDER BY table_name)
   FROM (SELECT table_name, string_agg(quote_ident(column_name), ',' ORDER BY ordinal_position) AS cols
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'
         GROUP BY table_name) x" > "$WORK/fingerprint.sql"
psql "${L[@]}" -d "$DB" -XAtq -v ON_ERROR_STOP=1 -f "$WORK/fingerprint.sql" > "$WORK/fp-before.txt"
ok "$(wc -l < "$WORK/fp-before.txt") tables fingerprinted ($(awk -F'|' '{s+=$2} END {print s}' "$WORK/fp-before.txt") rows)"

# ---------------------------------------------------------------- 5. the release migrations
say "[5/7] Apply the release migrations (prisma migrate deploy, exactly as on Render)"
export DATABASE_URL="postgresql://postgres@localhost/$DB?host=$WORK/pg/sock"
export CHECKPOINT_DISABLE=1 PRISMA_HIDE_UPDATE_MESSAGE=1
( cd "$API" && node_modules/.bin/prisma migrate deploy --schema prisma/schema.prisma ) > "$WORK/migrate.log" 2>&1 \
  || { sed 's/^/    /' "$WORK/migrate.log" | grep -v -i "password\|secret" | tail -20; fail "the release migrations failed on the restored copy"; }
APPLIED_AFTER=$(q "select count(*) from _prisma_migrations where finished_at is not null")
NEW_MIGRATIONS=$(q "select string_agg(migration_name, ', ') from (select migration_name from _prisma_migrations where finished_at is not null order by migration_name offset $APPLIED_BEFORE) x")
ok "applied $((APPLIED_AFTER - APPLIED_BEFORE)) migration(s): ${NEW_MIGRATIONS:-none}"
psql "${L[@]}" -d "$DB" -XAtq -v ON_ERROR_STOP=1 -f "$WORK/fingerprint.sql" > "$WORK/fp-after.txt"
if diff -q "$WORK/fp-before.txt" "$WORK/fp-after.txt" >/dev/null; then
  MIGRATIONS_KEPT_DATA=yes
  ok "every existing table, row and value is identical after the migrations"
else
  MIGRATIONS_KEPT_DATA=no
  printf '  \033[31mDIFFERENT\033[0m tables: %s\n' "$(diff "$WORK/fp-before.txt" "$WORK/fp-after.txt" | grep '^>' | cut -d'|' -f1 | tr -d '> ' | paste -sd, -)"
fi

# ---------------------------------------------------------------- 6. rehearsal with the release code
say "[6/7] Start the release, run the metadata backfill, check every document, link and download"
echo "  Paste each value from your password manager. Nothing is shown, logged or saved."
read_secret "  MASTER_KEY: "; MK="$REPLY_SECRET"
read_secret "  IP_HASH_SECRET: "; IH="$REPLY_SECRET"
read_secret "  ISSUER_SIGNING_SEED: "; IS="$REPLY_SECRET"
unset REPLY_SECRET
[ -n "$MK" ] && [ -n "$IH" ] && [ -n "$IS" ] || fail "a secret was empty"
set +e
printf '%s\n%s\n%s\n' "$MK" "$IH" "$IS" | ( cd "$API" && node dist/rehearsal.js ) > "$WORK/result.json" 2> "$WORK/rehearsal.err"
code=$?
set -e
unset MK IH IS
[ -s "$WORK/result.json" ] || { tail -5 "$WORK/rehearsal.err" | sed 's/^/    /'; fail "the rehearsal stopped without a result"; }
[ "$MIGRATIONS_KEPT_DATA" = yes ] || code=1

# ---------------------------------------------------------------- 7. report
say "[7/7] Result"
REPORT="$OUT/$NAME-rehearsal-$(date -u +%Y-%m-%dT%H%MZ).txt"
{
  echo "TrustPass release rehearsal"
  echo "Release:     $RELEASE"
  echo "Backup:      $NAME.7z (SHA-256 $(cut -d' ' -f1 "$IN/$NAME.7z.sha256"))"
  echo "Checked at:  $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
  echo "Environment: no network, RAM only, backup folder read-only, PostgreSQL $(q 'show server_version' | cut -d' ' -f1)"
  echo "Migrations:  $APPLIED_BEFORE already applied, $((APPLIED_AFTER - APPLIED_BEFORE)) applied now (${NEW_MIGRATIONS:-none})"
  echo "Existing data identical after the migrations: $MIGRATIONS_KEPT_DATA"
  echo
  cat "$WORK/result.json"
  echo
  if [ "$code" = 0 ]; then echo "RESULT: REHEARSAL PASSED"; else echo "RESULT: REHEARSAL FAILED (see reasons above)"; fi
} > "$REPORT"
sed 's/^/  /' "$WORK/result.json"
echo
if [ "$code" = 0 ]; then
  ok "REHEARSAL PASSED: migrations kept every value; every document, field, credential, link and download works with the release"
else
  printf '  \033[31mREHEARSAL FAILED\033[0m: see "reasons" above. Production was not touched.\n'
fi
ok "report: rehearsal-reports/$(basename "$REPORT") (no secrets, no document content)"
ok "the restored copy existed only in RAM and disappears when this container closes"
echo
exit "$code"
