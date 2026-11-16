# TrustPass demo script (about 8 minutes)

Prepare: the deployed site open on the projector, the presenter's phone, and one volunteer phone. Sign in as the presenter beforehand.

1. **The problem (30 s).** "When you apply for a job you send your whole certificate on WhatsApp. You lose control the moment you hit send."
2. **Get a signed credential (1 min).** Demo University > Issue my signed credential. Point at the green **Verified** panel and the six signed fields. Mention: the university is simulated, the Ed25519 signature is real.
3. **Share one field (1 min).** Share securely > tick *Enrollment status* only > recipient "Example Company" > 24 hours > Saudi Arabia only > Create. Show the link.
4. **Open it on the volunteer's phone (1 min).** The volunteer sees only "Enrollment status: Active", a Verified badge, and their approximate country. Ask them to look for the student ID: it is not there, because it never left the server.
5. **Watch it live (1 min).** Back on the presenter's screen: Access analytics shows the view and the country. A notification says "First view from Saudi Arabia".
6. **Country rule (1 min).** Sharing links > Countries > switch Saudi Arabia to the UAE only. The volunteer reloads: "Not available in your location". The denied attempt appears in analytics.
7. **Revoke (30 s).** Revoke the link. The volunteer reloads: "This link was revoked". Instant.
8. **Tampering (1 min).** Download the certificate PDF, change any byte (or re-save it in a PDF editor), and upload it on Verify a document: **Invalid: the document was modified after the issuer signed it.**
9. **Close with honesty (30 s).** Location is approximate, screenshots cannot be blocked (the watermark makes leaks traceable), and encryption is at rest on the server. Being clear about limits is part of good security.

Optional for an admin audience: Admin > Issuers > Revoke trust, then reopen any shared credential: it now verifies as Invalid. Restore trust afterwards.
