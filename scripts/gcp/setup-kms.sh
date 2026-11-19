#!/bin/bash
# TrustPass: one-time Google Cloud KMS setup (run in Google Cloud Shell)
# ---------------------------------------------------------------------
# Creates everything TrustPass needs in an EXISTING project that already has billing:
#   - Cloud KMS API enabled
#   - key ring "trustpass" in europe-west3 (Frankfurt, next to the Render database)
#   - keys "trustpass-prod-kek" (production) and "trustpass-test-kek" (CI tests only)
#   - service accounts "trustpass-app" (prod key only) and "trustpass-ci" (test key only),
#     each with ONE role (Cloud KMS CryptoKey Encrypter/Decrypter) on ONE key, nothing else
#   - optionally a $1 monthly budget alert
#   - a JSON key for trustpass-ci only, written to ~/trustpass-ci-key.json (mode 600)
#
# With --production it also creates the JSON key for trustpass-app (the day production moves to
# KMS), as one base64 line in ~/trustpass-app-key.b64 (mode 600), ready for Render. Without it no
# production credential is made. The script prints no secret.
# Safe to run twice: anything that already exists is kept.
#
#   bash setup-kms.sh <PROJECT_ID> [BILLING_ACCOUNT_ID] [--production]
set -euo pipefail
umask 077

PRODUCTION=0
ARGS=()
for a in "$@"; do if [ "$a" = "--production" ]; then PRODUCTION=1; else ARGS+=("$a"); fi; done
PROJECT="${ARGS[0]:?usage: bash setup-kms.sh <PROJECT_ID> [BILLING_ACCOUNT_ID] [--production]}"
BILLING="${ARGS[1]:-}"
LOCATION=europe-west3
RING=trustpass
PROD_KEY=trustpass-prod-kek
TEST_KEY=trustpass-test-kek
APP_SA="trustpass-app@${PROJECT}.iam.gserviceaccount.com"
CI_SA="trustpass-ci@${PROJECT}.iam.gserviceaccount.com"
ROLE=roles/cloudkms.cryptoKeyEncrypterDecrypter
CI_KEY_FILE="$HOME/trustpass-ci-key.json"
APP_KEY_FILE="$HOME/trustpass-app-key.b64"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok() { printf '  \033[32mOK\033[0m  %s\n' "$*"; }

say "[1/6] Project and billing"
gcloud config set project "$PROJECT" >/dev/null
enabled=$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)' 2>/dev/null || echo "")
[ "$enabled" = "True" ] || { echo "  Billing is not enabled on $PROJECT. Link a billing account first (Billing > My projects)."; exit 1; }
ok "billing enabled on $PROJECT"

say "[2/6] Cloud KMS API"
gcloud services enable cloudkms.googleapis.com
ok "cloudkms.googleapis.com enabled"

say "[3/6] Key ring and keys ($LOCATION)"
gcloud kms keyrings describe "$RING" --location "$LOCATION" >/dev/null 2>&1 || gcloud kms keyrings create "$RING" --location "$LOCATION"
for key in "$PROD_KEY" "$TEST_KEY"; do
  gcloud kms keys describe "$key" --keyring "$RING" --location "$LOCATION" >/dev/null 2>&1 ||
    gcloud kms keys create "$key" --keyring "$RING" --location "$LOCATION" --purpose encryption --protection-level software
  ok "key $key"
done

say "[4/6] Service accounts (one role on one key each)"
for sa in trustpass-app trustpass-ci; do
  gcloud iam service-accounts describe "$sa@${PROJECT}.iam.gserviceaccount.com" >/dev/null 2>&1 ||
    gcloud iam service-accounts create "$sa" --display-name "TrustPass ${sa#trustpass-} (KMS only)"
done
gcloud kms keys add-iam-policy-binding "$PROD_KEY" --keyring "$RING" --location "$LOCATION" \
  --member "serviceAccount:$APP_SA" --role "$ROLE" >/dev/null
gcloud kms keys add-iam-policy-binding "$TEST_KEY" --keyring "$RING" --location "$LOCATION" \
  --member "serviceAccount:$CI_SA" --role "$ROLE" >/dev/null
ok "trustpass-app -> $PROD_KEY only"
ok "trustpass-ci  -> $TEST_KEY only"

say "[5/6] Budget alert"
if [ -n "$BILLING" ]; then
  gcloud services enable billingbudgets.googleapis.com
  if gcloud billing budgets list --billing-account "$BILLING" --format='value(displayName)' | grep -qx trustpass-kms; then
    ok "budget trustpass-kms already exists"
  else
    gcloud billing budgets create --billing-account "$BILLING" --display-name trustpass-kms \
      --budget-amount 1USD --filter-projects "projects/$PROJECT" \
      --threshold-rule percent=0.5 --threshold-rule percent=1.0 >/dev/null
    ok "budget trustpass-kms: email alerts at \$0.50 and \$1.00 per month"
  fi
else
  echo "  skipped (no billing account id given); create one in Billing > Budgets & alerts"
fi

say "[6/6] CI test credential"
if [ -f "$CI_KEY_FILE" ]; then
  ok "$CI_KEY_FILE already exists (not replaced)"
else
  gcloud iam service-accounts keys create "$CI_KEY_FILE" --iam-account "$CI_SA" >/dev/null
  chmod 600 "$CI_KEY_FILE"
  ok "created $CI_KEY_FILE (test key only; never use it in production)"
fi

if [ "$PRODUCTION" = 1 ]; then
  say "[6b] Production credential (trustpass-app, production key only)"
  if [ -f "$APP_KEY_FILE" ]; then
    ok "$APP_KEY_FILE already exists (not replaced)"
  else
    tmp="$(mktemp)"
    gcloud iam service-accounts keys create "$tmp" --iam-account "$APP_SA" >/dev/null
    base64 -w0 "$tmp" > "$APP_KEY_FILE"
    shred -u "$tmp" 2>/dev/null || rm -f "$tmp"
    chmod 600 "$APP_KEY_FILE"
    ok "created $APP_KEY_FILE (one line, base64; production key only)"
  fi
fi

TEST_NAME="projects/$PROJECT/locations/$LOCATION/keyRings/$RING/cryptoKeys/$TEST_KEY"
PROD_NAME="projects/$PROJECT/locations/$LOCATION/keyRings/$RING/cryptoKeys/$PROD_KEY"
say "Done. Values for GitHub (Settings > Secrets and variables > Actions > New repository secret):"
echo "  GCP_TEST_KMS_KEY_NAME          = $TEST_NAME"
echo "  GCP_TEST_SERVICE_ACCOUNT_JSON  = the whole content of $CI_KEY_FILE"
echo
if [ "$PRODUCTION" = 1 ]; then
  say "Values for Render (trustpass > Environment):"
  echo "  KEY_PROVIDER                   = gcp-kms"
  echo "  GCP_KMS_KEY_NAME               = $PROD_NAME"
  echo "  GCP_SERVICE_ACCOUNT_JSON       = the one line in $APP_KEY_FILE   (show it with: cat $APP_KEY_FILE)"
  echo
  echo "  After saving both, delete the local copies: shred -u $CI_KEY_FILE $APP_KEY_FILE"
else
  echo "  Production key name (for later, not needed now): $PROD_NAME"
  echo "  After saving the GitHub secret, delete the local copy: shred -u $CI_KEY_FILE"
fi
