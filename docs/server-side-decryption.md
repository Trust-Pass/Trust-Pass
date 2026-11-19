# Server-side decryption: what it means for security

TrustPass encrypts everything at rest, but the **server holds the ability to decrypt**. It is
not end-to-end encrypted. This page explains why, what that protects against, what it does not,
and what would change if we went further.

## Why the server decrypts

The core features need the plaintext on the server, at the moment of a request:

| Feature | What the server must read | Where |
|---|---|---|
| Owner views a file or its fields | file, field values, title | `modules/documents.ts` |
| Recipient opens a link | only the fields the owner chose; the file only if included | `modules/access.ts` |
| Watermarked view-only PDF | the file, to stamp the recipient's name and time on every page | `lib/pdf.ts` |
| Selective disclosure (SD-JWT) | the signed credential, to send only the chosen claims | `modules/access.ts` |
| Server-checked rules | expiry, country and recipient are enforced before anything is decrypted | `modules/access.ts` |
| Verification page | the credential, to check the issuer's Ed25519 signature | `modules/verification.ts` |

With end-to-end encryption, the recipient's browser would need the key. Then the server could no
longer enforce expiry, country rules, revocation or watermarking: anyone who once received the
key and ciphertext could decrypt them forever. For TrustPass's purpose (the owner keeps control
*after* sharing), server-side enforcement is the deliberate choice.

## What is protected today

| Threat | Protected? | How |
|---|---|---|
| Stolen database or backup | **Yes** | Files, field values, credentials, titles, labels, recipient names and hashes are AES-256-GCM ciphertext. Each document has its own key, wrapped by the key-encryption key, which is not in the database. |
| Storage tampering | **Yes** | GCM authentication plus a sealed SHA-256: any changed byte is refused, logged, and the owner and admins are alerted. |
| Moving ciphertext between rows | **Yes** | Every sealed value is bound to its row and owner by additional authenticated data. |
| Logs, notifications, error messages | **Yes** | They contain ids only. Titles and names are filled in when an authorised user reads them. |
| A recipient seeing more than allowed | **Yes** | Hidden fields are never decrypted for a recipient and never leave the server. |
| An admin browsing documents | **Yes, in the app** | No admin endpoint decrypts documents; Admin > Health shows counts only. |
| Leaked application secret (`MASTER_KEY`) together with the database | **No, in `env` mode** | Whoever holds both can decrypt everything offline. This is the main reason to move to Cloud KMS. |
| Compromised running server (code execution, malicious deploy, hosting-provider insider) | **No** | A process that can serve documents can also decrypt them. This is inherent in server-side decryption. |

## Residual risks and how they are reduced

1. **Key in the environment (`KEY_PROVIDER=env`, today).** `MASTER_KEY` sits in Render's
   environment. Reduction: move to Google Cloud KMS. The key-encryption key then never leaves
   Google's hardware-backed service; a copied database plus a copied environment no longer decrypts
   anything offline, every unwrap is an audited API call, and access can be cut in one click by
   disabling the service account or key.
2. **Running-process compromise.** An attacker with code execution on the server can request
   unwraps while they are inside. Reduction: KMS audit logs show the volume of unwraps, so unusual
   activity is visible; disabling the KMS key stops all decryption at once; keys are zeroed in memory
   after use (`fill(0)`); dependencies are audited in CI; secrets scan on every commit.
3. **Plaintext in memory during a request.** Decrypted bytes exist briefly in the Node process and
   are not written to disk, logs or caches (`Cache-Control: no-store, private`). A heap dump of the
   live process could contain them.
4. **Hosting provider.** Render can technically see the process and environment. Cloud KMS limits
   this to the time an attacker controls the running service; it does not remove it.
5. **What recipients do.** Once a field or watermarked file is shown, the recipient can photograph
   it. The watermark makes a leak traceable; no website can prevent it.

## Options if stronger guarantees are needed later

| Option | Gains | Costs |
|---|---|---|
| Cloud KMS (planned) | No offline decryption with stolen database + environment; audit log; kill switch | ~$0.12/month; Google Cloud account |
| Owner-held "vault" documents, encrypted in the browser with a passphrase | Server can never read them | They cannot be shared with server-enforced rules, watermarks or selective disclosure; a forgotten passphrase loses the document |
| Confidential computing (e.g. AMD SEV hosts) | Protects memory from the host | Not available on Render; much higher cost |

## Summary for users

TrustPass protects stored documents against theft of the database or backups, against tampering,
and against recipients seeing more than the owner chose. It does **not** protect against someone
who takes control of the running server: like most document-sharing services, the server has to
decrypt in order to enforce the owner's rules. This is stated in the README under *Honest
limitations* and on the landing page.
