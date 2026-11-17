#!/bin/bash
# TrustPass: encrypted production backup + local restore drill
# ------------------------------------------------------------
# Runs INSIDE the local Docker image trustpass-pgtools:18 (postgres:18 + ca-certificates + 7zip):
#
#   docker run --rm -it --tmpfs /work:rw,size=512m,mode=0711 -v "${PWD}:/backup" trustpass-pgtools:18 bash /backup/trustpass-backup-drill.sh
#
# What it does:
#   1. Read-only pg_dump of production over TLS verify-full, into /work (RAM only, never on disk).
#   2. Encrypts the dump with 7-Zip (AES-256, encrypted file names), still in RAM.
#   3. Proves the archive really is encrypted, then copies ONLY the encrypted archive to /backup.
#   4. Decrypts the archive from /backup back into RAM and checks it is byte-identical.
#   5. Restores it into a throw-away PostgreSQL that lives in RAM and only listens on a
#      local socket (no network), then counts rows.
#   6. Writes a report (no secrets) next to the archive.
# The container is started with --rm and /work is RAM: when it ends, every unencrypted copy is gone.
#
# Passwords are only ever typed at hidden prompts. Nothing secret is written, logged or printed.
# The production database is only read: pg_dump runs in a READ ONLY transaction and the session
# is forced to default_transaction_read_only=on.
set -euo pipefail
umask 077

DB_NAME="trustpass_nxbq"
DB_USER="trustpass"
WORK="/work"
OUT="/backup"
SELFTEST="${TRUSTPASS_DRILL_SELFTEST:-0}"   # only used by the developer test harness

# Row counts read from production (read-only) on 17 Nov 2026 22:00 +03, for comparison only.
declare -A REFERENCE=(
  [_prisma_migrations]=1 [access_logs]=13 [allowed_countries]=5 [credentials]=1
  [document_claims]=6 [document_keys]=2 [documents]=4 [issuers]=1 [notifications]=9
  [organization_members]=0 [organizations]=0 [password_reset_tokens]=0 [security_events]=34
  [sessions]=8 [sharing_links]=8 [sharing_permissions]=2 [stored_objects]=2
  [system_settings]=0 [users]=6 [verification_records]=4
)

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m  %s\n' "$*"; }
fail() { printf '\n  \033[31mSTOPPED:\033[0m %s\n\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -f "$WORK/pg/data/postmaster.pid" ]; then
    gosu postgres pg_ctl -D "$WORK/pg/data" -m fast -w stop >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- 0. pre-flight
say "[0/6] Checks before starting"
[ "$SELFTEST" = 1 ] || grep -qE "^[^ ]+ $WORK tmpfs " /proc/mounts \
  || fail "$WORK is not a RAM disk. Start the container with --tmpfs /work:rw,size=512m,mode=0711"
ok "$WORK is RAM only"
[ -d "$OUT" ] && [ -w "$OUT" ] || fail "$OUT is not mounted. Run the command from C:\\TrustPass-Backups"
ok "backup folder mounted"
command -v 7zz >/dev/null || fail "7-Zip (7zz) is not in this image. Rebuild trustpass-pgtools:18 with the 7zip package"
command -v pg_dump >/dev/null && command -v pg_restore >/dev/null && command -v initdb >/dev/null \
  || fail "PostgreSQL tools missing"
ok "$(pg_dump --version), $(7zz | sed -n '2p' | cut -c1-40)"
if [ "$SELFTEST" != 1 ]; then
  CA=$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo 0)
  [ "$CA" -gt 50 ] || fail "trusted CA certificates missing in the image"
  ok "$CA trusted CA certificates"
fi

STAMP="$(date -u +%Y-%m-%dT%H%MZ)"
NAME="trustpass-$STAMP"
ARCHIVE="$OUT/$NAME.7z"
[ ! -e "$ARCHIVE" ] || fail "$ARCHIVE already exists; nothing was overwritten"

# ---------------------------------------------------------------- host name
if [ "$SELFTEST" = 1 ]; then
  DB_HOST="$TRUSTPASS_DRILL_SELFTEST_HOST"
else
  echo
  echo "  Paste ONLY the host name from Render > trustpass-db > Info"
  echo "  (looks like dpg-xxxxxxxx-a.frankfurt-postgres.render.com). No password, no postgres:// URL."
  read -r -p "  Host: " DB_HOST
  DB_HOST="${DB_HOST//[$'\r\t ']/}"
  # Refuse anything that could contain a password or a full connection string.
  [[ "$DB_HOST" =~ ^dpg-[a-z0-9]+-a(\.[a-z0-9-]+)?\.render\.com$ ]] \
    || fail "that does not look like a Render host name (only dpg-...-a.<region>-postgres.render.com is accepted). Nothing was sent."
fi
ok "host accepted"

# ---------------------------------------------------------------- 1. read-only dump into RAM
say "[1/6] Read-only backup of production into RAM"
echo "  Type the DATABASE password (from Render > trustpass-db > Info). Nothing is shown while typing."
DUMP="$WORK/$NAME.dump"
if [ "$SELFTEST" = 1 ]; then
  PGOPTIONS='-c default_transaction_read_only=on' \
    pg_dump --host="$DB_HOST" --username="$DB_USER" --dbname="$DB_NAME" --no-password \
            --format=custom --file="$DUMP"
else
  PGSSLMODE=verify-full PGSSLROOTCERT=system PGCONNECT_TIMEOUT=20 \
  PGOPTIONS='-c default_transaction_read_only=on' \
    pg_dump --host="$DB_HOST" --port=5432 --username="$DB_USER" --dbname="$DB_NAME" --password \
            --format=custom --file="$DUMP" \
    || fail "pg_dump did not finish. Production was not changed (read-only session)."
fi
pg_restore --list "$DUMP" > "$WORK/toc.txt" || fail "the dump is not readable"
TABLES_IN_DUMP=$(grep -c ' TABLE DATA public ' "$WORK/toc.txt" || true)
ok "dump in RAM: $(stat -c %s "$DUMP") bytes, $TABLES_IN_DUMP tables with data, verify-full TLS, read-only"

# ---------------------------------------------------------------- 2. encrypt in RAM
say "[2/6] Encrypt with 7-Zip AES-256 (file names encrypted too)"
echo "  Choose a NEW strong passphrase (at least 20 characters or 5 random words)."
echo "  Save it in your password manager FIRST, in a different entry from MASTER_KEY."
echo "  7-Zip will ask for it twice. Nothing is shown while typing."
WORK_ARCHIVE="$WORK/$NAME.7z"
7zz a -t7z -mhe=on -mx=9 -p "$WORK_ARCHIVE" "$DUMP" \
  || fail "7-Zip could not create the archive"

# Prove it is encrypted: with a wrong password even the file list must be unreadable.
if 7zz l -p'definitely-not-the-passphrase-0f3a' "$WORK_ARCHIVE" >/dev/null 2>&1; then
  fail "the archive is NOT encrypted (was the passphrase empty?). Nothing was copied to your disk."
fi
if 7zz l -p'definitely-not-the-passphrase-0f3a' "$WORK_ARCHIVE" 2>&1 | grep -q "$NAME.dump"; then
  fail "file names are readable without the passphrase. Nothing was copied to your disk."
fi
ok "encrypted (wrong passphrase cannot even list it)"

# ---------------------------------------------------------------- 3. only the encrypted file goes to disk
cp "$WORK_ARCHIVE" "$ARCHIVE"
( cd "$OUT" && sha256sum "$NAME.7z" > "$NAME.7z.sha256" )
ok "saved $NAME.7z ($(stat -c %s "$ARCHIVE") bytes) and its SHA-256"

# ---------------------------------------------------------------- 4. decrypt from disk into RAM, compare
say "[3/6] Integrity check: decrypt the saved archive back into RAM"
echo "  Type the 7-Zip passphrase once more."
mkdir -p "$WORK/check"
7zz x -p -o"$WORK/check" "$ARCHIVE" || fail "the archive could not be decrypted (wrong passphrase or damaged file)"
cmp -s "$DUMP" "$WORK/check/$NAME.dump" || fail "the decrypted copy differs from the original dump"
( cd "$OUT" && sha256sum -c --quiet "$NAME.7z.sha256" ) || fail "SHA-256 of the saved archive does not match"
ok "archive opens with the passphrase, CRC OK, byte-identical to the dump, SHA-256 OK"

# ---------------------------------------------------------------- 5. restore drill (RAM, no network)
say "[4/6] Restore drill into a temporary PostgreSQL (RAM only, local socket, no network)"
mkdir -p "$WORK/pg"
chown postgres:postgres "$WORK/pg"
gosu postgres mkdir -p "$WORK/pg/data" "$WORK/pg/sock"
gosu postgres initdb -D "$WORK/pg/data" -U postgres -A trust --no-sync >/dev/null
gosu postgres pg_ctl -D "$WORK/pg/data" -l "$WORK/pg/log" -w \
  -o "-c listen_addresses='' -c unix_socket_directories=$WORK/pg/sock -c fsync=off" start >/dev/null
L=(-h "$WORK/pg/sock" -U postgres)
createdb "${L[@]}" restore_drill
pg_restore "${L[@]}" --dbname=restore_drill --no-owner --no-privileges --exit-on-error \
  "$WORK/check/$NAME.dump" || fail "pg_restore failed (see above). Production was not touched."
ok "restored with --exit-on-error: no errors"

say "[5/6] Comparing the restored copy"
q() { psql "${L[@]}" -d restore_drill -XAtq -v ON_ERROR_STOP=1 -c "$1"; }
REPORT="$WORK/report.txt"
{
  echo "TrustPass backup and restore drill"
  echo "Backup file:      $NAME.7z"
  echo "SHA-256:          $(cut -d' ' -f1 "$OUT/$NAME.7z.sha256")"
  echo "Archive size:     $(stat -c %s "$ARCHIVE") bytes (dump $(stat -c %s "$DUMP") bytes)"
  echo "Taken (UTC):      $STAMP"
  echo "Source:           Render trustpass-db ($DB_NAME), pg_dump $(pg_dump --version | awk '{print $3}'), TLS verify-full, read-only"
  echo "Encryption:       7-Zip 7z, AES-256, encrypted headers; passphrase in password manager"
  echo "Restore target:   temporary PostgreSQL $(q 'show server_version'), RAM only, no network"
  echo
  printf '%-24s %9s %12s\n' "table" "restored" "ref 22:00"
} > "$REPORT"
MISMATCH=0; TOTAL=0; NTABLES=0
while read -r t; do
  n=$(q "select count(*) from public.\"$t\"")
  r="${REFERENCE[$t]:--}"
  flag=""; [ "$r" = "-" ] || [ "$n" = "$r" ] || { flag="  changed since 22:00"; MISMATCH=$((MISMATCH+1)); }
  printf '%-24s %9s %12s%s\n' "$t" "$n" "$r" "$flag" >> "$REPORT"
  TOTAL=$((TOTAL+n)); NTABLES=$((NTABLES+1))
done < <(q "select tablename from pg_tables where schemaname='public' order by 1")
MIGR=$(q "select string_agg(migration_name, ', ' order by migration_name) from _prisma_migrations where finished_at is not null")
EMPTY_BLOBS=$(q "select count(*) from stored_objects where octet_length(data) = 0" 2>/dev/null || echo "n/a")
ORPHAN_KEYS=$(q "select count(*) from documents d where d.kind='file' and d.deleted_at is null and not exists (select 1 from document_keys k where k.document_id=d.id)" 2>/dev/null || echo "n/a")
{
  echo
  echo "Tables restored:  $NTABLES (expected 20), rows: $TOTAL"
  echo "Migrations:       $MIGR"
  echo "Empty stored files: $EMPTY_BLOBS   File documents without a key: $ORPHAN_KEYS"
  echo "Differences vs 22:00 reference: $MISMATCH (normal if the site was used in between)"
} >> "$REPORT"
cat "$REPORT" | sed 's/^/  /'

[ "$NTABLES" = 20 ] || fail "expected 20 tables, restored $NTABLES"

say "[6/6] Result"
echo "RESULT: RESTORE DRILL OK (structure and data; document decryption not tested here)" >> "$REPORT"
cp "$REPORT" "$OUT/$NAME-report.txt"
ok "RESTORE DRILL OK"
ok "kept on your disk: $NAME.7z, $NAME.7z.sha256, $NAME-report.txt (all safe to keep; only the .7z holds data, encrypted)"
ok "all unencrypted copies were only in RAM and disappear when this container closes"
echo
