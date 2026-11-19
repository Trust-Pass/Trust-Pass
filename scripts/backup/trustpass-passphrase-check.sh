#!/bin/bash
# TrustPass: diagnose why a backup will not decrypt (read-only, nothing written anywhere)
# --------------------------------------------------------------------------------------
# Asks for the backup passphrase at a hidden prompt and tells you, WITHOUT showing it:
#   - which 7-Zip build is in the image
#   - what was received: length, spaces or line breaks at the ends, non-ASCII characters
#   - the exact 7-Zip result of an integrity TEST of the archive (no files are extracted)
#   - if the passphrase has spaces/line breaks at the ends, whether the trimmed version works
#
#   docker run --rm -it --network none -v "${PWD}:/backup:ro" \
#     trustpass-pgtools:18 bash /backup/trustpass-passphrase-check.sh trustpass-2026-11-18T1458Z.7z
#
# The backup folder is mounted read-only and the container has no network. Nothing is saved:
# no report, no extracted data. The passphrase is passed to 7-Zip through a pipe only.
set -euo pipefail
umask 077
IN=/backup
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }

[ -t 0 ] || { echo "Start the container with -it so the passphrase can be typed at a hidden prompt."; exit 1; }
nets=$(ls /sys/class/net | grep -v '^lo$' || true)
[ -z "$nets" ] || { echo "This container has network access. Start it with --network none."; exit 1; }
touch "$IN/.write-test" 2>/dev/null && { rm -f "$IN/.write-test"; echo "Mount the folder read-only (:ro)."; exit 1; }

ARCHIVE="$IN/$(basename "${1:?give the archive name, e.g. trustpass-2026-11-18T1458Z.7z}")"
[ -f "$ARCHIVE" ] || { echo "Not found: $(basename "$ARCHIVE")"; exit 1; }

say "[1/3] Tools"
info "7-Zip: $(7zz | sed -n '2p' | cut -c1-60)"
info "Archive: $(basename "$ARCHIVE"), $(stat -c %s "$ARCHIVE") bytes"

say "[2/3] Passphrase (paste it from your password manager; nothing is shown)"
while IFS= read -r -s -t 0.3 -n 4096 _junk 2>/dev/null; do :; done
IFS= read -r -s -p "  Backup passphrase: " P || P=""
echo
raw_len=${#P}
has_cr=no; [[ "$P" == *$'\r'* ]] && has_cr=yes
P="${P%$'\r'}"
lead=no; [[ "$P" =~ ^[[:space:]] ]] && lead=yes
trail=no; [[ "$P" =~ [[:space:]]$ ]] && trail=yes
nonascii=no; LC_ALL=C; [[ "$P" == *[$'\x80'-$'\xff']* ]] && nonascii=yes
ctrl=no; [[ "$P" == *[$'\x01'-$'\x1f']* ]] && ctrl=yes
info "characters received:          $raw_len (after removing a final carriage return: ${#P})"
info "carriage return in input:     $has_cr"
info "space at the start / end:     $lead / $trail"
info "non-ASCII characters:         $nonascii"
info "other control characters:     $ctrl"
[ "${#P}" -gt 0 ] || { info "RESULT: nothing was received. Paste again, after the prompt appears."; exit 1; }

try() { # prints 7-Zip's verdict lines only (they never contain the passphrase)
  local out
  out=$(printf '%s\n' "$1" | 7zz t -bso1 -bse1 -bsp0 "$ARCHIVE" 2>&1 || true)
  if grep -q "Everything is Ok" <<<"$out"; then echo OK; return; fi
  grep -oiE "wrong password|headers error|data error|crc failed|unsupported method|can ?not open( the file)? as( an)? archive|unexpected end of archive|is not archive" <<<"$out" | sort -u | paste -sd ',' || echo "unknown error"
}

say "[3/3] 7-Zip integrity test (nothing is extracted)"
r=$(try "$P")
info "with the passphrase exactly as received: $r"
if [ "$r" != OK ] && { [ "$lead" = yes ] || [ "$trail" = yes ]; }; then
  t="${P#"${P%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
  info "with spaces at the ends removed:         $(try "$t")"
fi
unset P t
echo
if [ "$r" = OK ]; then
  info "RESULT: this passphrase decrypts the archive. The recovery check should pass with it."
else
  info "RESULT: 7-Zip says \"$r\" for this passphrase."
fi
