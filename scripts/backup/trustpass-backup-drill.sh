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
# Passwords are only ever typed at hidden prompts (the database password at pg_dump's prompt, the
# backup passphrase at this script's own prompt). 7-Zip never prompts: on Linux it would echo.
# Nothing secret is written, logged or printed.
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

# Read a secret at a hidden prompt. Keys typed ahead (for example the extra line break of a
# paste) are discarded first, so they can never become the answer to the next prompt.
read_secret() {
  local _junk
  while IFS= read -r -s -t 0.3 -n 4096 _junk 2>/dev/null; do :; done
  IFS= read -r -s -p "$1" REPLY_SECRET || REPLY_SECRET=""
  echo
  REPLY_SECRET="${REPLY_SECRET%$'\r'}"
}

# 7-Zip on Linux reads the passphrase from standard input and does NOT hide it, so the script
# never lets 7-Zip prompt: it hands over the passphrase through a pipe (printf is a shell
# built-in, so the passphrase never appears in a process list or on screen).
# Note: for "a" a bare -p means "ask for a password"; for "x"/"t" a bare -p means "the password
# is EMPTY" (7-Zip 25/26 behaviour), so extraction must be run WITHOUT -p to make it read one.
z7a() { printf '%s\n' "$PASS" | 7zz a -p -bso0 -bsp0 "$@"; }
z7x() { printf '%s\n' "$PASS" | 7zz x -y -bso0 -bsp0 "$@"; }

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
[ "$SELFTEST" = 1 ] || [ -z "$(ls -A "$WORK")" ] || fail "$WORK is not empty; start a new container"
[ -d "$OUT" ] && [ -w "$OUT" ] || fail "$OUT is not mounted. Run the command from C:\\TrustPass-Backups"
ok "backup folder mounted"
command -v 7zz >/dev/null || fail "7-Zip (7zz) is not in this image. Rebuild trustpass-pgtools:18 from scripts/backup/Dockerfile (package 7zip-standalone)"
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
  # External host of trustpass-db (Render id dpg-dbthlre7bikc73cmpuvg-a, region frankfurt).
  # A host name is not a secret; TLS verify-full below proves the server really is this host.
  DEFAULT_HOST="dpg-dbthlre7bikc73cmpuvg-a.frankfurt-postgres.render.com"
  echo
  echo "  Database host. Press Enter to use trustpass-db's external host:"
  echo "    $DEFAULT_HOST"
  echo "  or paste the EXTERNAL host name from Render > trustpass-db > Info > External Database URL"
  echo "  (only the part between @ and :5432). No password, no postgres:// URL."
  read -r -p "  Host [Enter = default]: " DB_HOST
  DB_HOST="${DB_HOST//[$'\r\t ']/}"
  DB_HOST="${DB_HOST,,}"
  [ -n "$DB_HOST" ] || DB_HOST="$DEFAULT_HOST"
  if [[ "$DB_HOST" =~ ^dpg-[a-z0-9]+-a$ ]]; then
    fail "that is the INTERNAL host name (only works inside Render). Use the External one, which ends in .frankfurt-postgres.render.com. Nothing was sent."
  fi
  # Refuse anything that could contain a password or a full connection string.
  [[ "$DB_HOST" =~ ^dpg-[a-z0-9]+-a\.[a-z0-9]+-postgres\.render\.com$ ]] \
    || fail "not a Render external host name (expected dpg-<id>-a.<region>-postgres.render.com, without postgres://, user, password, :5432 or /database). Nothing was sent."
  [ "$DB_HOST" = "$DEFAULT_HOST" ] || echo "  Note: this is not trustpass-db's usual host; continuing because it is a valid Render host."
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
echo "  Choose a NEW backup passphrase and save it in your password manager FIRST"
echo "  (a different entry from MASTER_KEY). Rules: at least 16 characters, English"
echo "  letters, digits and symbols only, no space at the start or end."
echo "  You will type it twice. Nothing is shown while typing."
PASS=""
for attempt in 1 2 3; do
  read_secret "  Backup passphrase: ";        P1="$REPLY_SECRET"
  read_secret "  Same passphrase again: ";    P2="$REPLY_SECRET"
  if [ "$P1" != "$P2" ]; then echo "  The two entries are different. Try again ($attempt/3)."; continue; fi
  if [ "${#P1}" -lt 16 ]; then echo "  Too short (${#P1} characters, need 16 or more). Try again ($attempt/3)."; continue; fi
  if [ -n "$(printf '%s' "$P1" | LC_ALL=C tr -d '\040-\176')" ]; then
    echo "  Contains non-English characters (keyboard layout?). Use English letters, digits, symbols. Try again ($attempt/3)."; continue
  fi
  if [ "$P1" != "${P1# }" ] || [ "$P1" != "${P1% }" ]; then echo "  Starts or ends with a space. Try again ($attempt/3)."; continue; fi
  PASS="$P1"; break
done
unset P1 P2 REPLY_SECRET
[ -n "$PASS" ] || fail "no valid passphrase after 3 attempts. Nothing was saved to your disk."
ok "passphrase accepted (${#PASS} characters; never shown, logged or saved by this script)"

WORK_ARCHIVE="$WORK/$NAME.7z"
z7a -t7z -mhe=on -mx=9 "$WORK_ARCHIVE" "$DUMP" || fail "7-Zip could not create the archive"

# Prove it is encrypted: with a wrong password even the file list must be unreadable.
if 7zz l -p'definitely-not-the-passphrase-0f3a' "$WORK_ARCHIVE" >/dev/null 2>&1; then
  fail "the archive is NOT encrypted. Nothing was copied to your disk."
fi
if 7zz l -p'definitely-not-the-passphrase-0f3a' "$WORK_ARCHIVE" 2>&1 | grep -q "$NAME.dump"; then
  fail "file names are readable without the passphrase. Nothing was copied to your disk."
fi
ok "encrypted (a wrong passphrase cannot even list it)"

# Integrity in RAM before anything is written to disk.
mkdir -p "$WORK/check"
z7x -o"$WORK/check" "$WORK_ARCHIVE" || fail "the new archive could not be decrypted in RAM. Nothing was copied to your disk."
cmp -s "$DUMP" "$WORK/check/$NAME.dump" || fail "decrypted copy differs from the dump. Nothing was copied to your disk."
rm -f "$WORK/check/$NAME.dump"
ok "decrypts with the passphrase and is byte-identical to the dump"

# ---------------------------------------------------------------- 3. check the saved passphrase
say "[3/6] Check the passphrase you SAVED"
echo "  Copy the passphrase FROM YOUR PASSWORD MANAGER and paste it here (not from memory)."
echo "  This proves the saved copy is right before the backup is written to your disk."
SAVED_OK=0
for attempt in 1 2 3; do
  read_secret "  Passphrase from password manager: "
  if [ "$REPLY_SECRET" = "$PASS" ]; then SAVED_OK=1; break; fi
  echo "  Does not match what you typed in step 2. Check the password manager entry ($attempt/3)."
done
unset REPLY_SECRET
[ "$SAVED_OK" = 1 ] || fail "the saved passphrase does not match. Nothing was copied to your disk; fix the password manager entry and run again."
ok "password manager entry matches"

# ---------------------------------------------------------------- only the encrypted file goes to disk
cp "$WORK_ARCHIVE" "$ARCHIVE"
( cd "$OUT" && sha256sum "$NAME.7z" > "$NAME.7z.sha256" )
ok "saved $NAME.7z ($(stat -c %s "$ARCHIVE") bytes) and its SHA-256"

# ---------------------------------------------------------------- 4. decrypt the saved file into RAM, compare
say "[4/6] Integrity check of the file on disk"
z7x -o"$WORK/check" "$ARCHIVE" || fail "the saved archive could not be decrypted (damaged file?)"
unset PASS
cmp -s "$DUMP" "$WORK/check/$NAME.dump" || fail "the saved archive differs from the original dump"
( cd "$OUT" && sha256sum -c --quiet "$NAME.7z.sha256" ) || fail "SHA-256 of the saved archive does not match"
ok "saved archive decrypts, CRC OK, byte-identical to the dump, SHA-256 OK"

# ---------------------------------------------------------------- 5. restore drill (RAM, no network)
say "[5/6] Restore drill into a temporary PostgreSQL (RAM only, local socket, no network)"
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

say "    Comparing the restored copy"
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

# 20 tables on main; later releases add tables (e.g. key_encryption_keys with E2).
[ "$NTABLES" -ge 20 ] || fail "expected at least 20 tables, restored $NTABLES"

# ---------------------------------------------------------------- 6. optional: prove the saved secrets
SECRETS_RESULT="not checked"
if [ "$SELFTEST" != 1 ] && [ -f "$OUT/verify-secrets.mjs" ] && command -v node >/dev/null; then
  say "[6/7] Optional: prove that your saved secrets open this backup"
  echo "  This uses the copies in your password manager to decrypt every document of the restored"
  echo "  copy, here in RAM. Nothing is shown, logged or saved; only OK / WRONG is reported."
  read -r -p "  Check MASTER_KEY and ISSUER_SIGNING_SEED now? [y/N] " answer
  if [[ "$answer" =~ ^[Yy] ]]; then
    psql "${L[@]}" -d restore_drill -XAtq -v ON_ERROR_STOP=1 -c "
      SELECT json_build_object(
        'documents', COALESCE((SELECT json_agg(to_jsonb(d) || jsonb_build_object('file', encode(so.data, 'hex'), 'key', to_jsonb(k)))
                               FROM documents d LEFT JOIN document_keys k ON k.document_id = d.id
                               LEFT JOIN stored_objects so ON so.key = d.storage_key), '[]'::json),
        'links', COALESCE((SELECT json_agg(json_build_object('id', id, 'token_hash', token_hash, 'token_encrypted', encode(token_encrypted, 'hex')))
                           FROM sharing_links), '[]'::json),
        'issuers', COALESCE((SELECT json_agg(public_key_jwk) FROM issuers), '[]'::json),
        'kmsKeys', CASE WHEN to_regclass('key_encryption_keys') IS NULL THEN 0 ELSE 1 END)" > "$WORK/export.json"
    read_secret "  MASTER_KEY (paste from the password manager): "; MK="$REPLY_SECRET"
    read_secret "  ISSUER_SIGNING_SEED (paste, or press Enter to skip): "; IS="$REPLY_SECRET"
    unset REPLY_SECRET
    set +e
    printf '%s\n%s\n' "$MK" "$IS" | node "$OUT/verify-secrets.mjs" "$WORK/export.json" > "$WORK/secrets.json"
    code=$?
    set -e
    unset MK IS
    rm -f "$WORK/export.json"
    sed 's/^/  /' "$WORK/secrets.json"
    { echo; echo "Saved secrets check:"; cat "$WORK/secrets.json"; } >> "$REPORT"
    if [ "$code" = 0 ]; then SECRETS_RESULT="OK"; ok "your saved secrets open this backup"; else SECRETS_RESULT="FAILED"; echo "  WARNING: a saved secret does not match (see above). Fix the password manager entry from Render > Environment."; fi
  fi
fi

say "[7/7] Result"
echo "Saved secrets: $SECRETS_RESULT" >> "$REPORT"
echo "RESULT: RESTORE DRILL OK (structure and data$([ "$SECRETS_RESULT" = OK ] && echo '; every document decrypted with the saved MASTER_KEY'))" >> "$REPORT"
cp "$REPORT" "$OUT/$NAME-report.txt"
ok "RESTORE DRILL OK"
ok "kept on your disk: $NAME.7z, $NAME.7z.sha256, $NAME-report.txt (all safe to keep; only the .7z holds data, encrypted)"
ok "all unencrypted copies were only in RAM and disappear when this container closes"
echo
