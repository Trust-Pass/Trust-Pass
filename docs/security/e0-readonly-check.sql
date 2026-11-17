-- E0: live check that documents are encrypted at rest.
--
-- SAFE TO RUN ON PRODUCTION:
--   * runs inside a READ ONLY transaction (PostgreSQL rejects any write) and ends with ROLLBACK
--   * returns only counts and yes/no answers: no file bytes, keys, IVs, titles,
--     field values, names, emails or ids are ever printed
--   * a 60-second statement timeout stops it if the database is slow
--
-- How to run: Render dashboard > trustpass-db > Connect > copy the PSQL command, run it in
-- your own terminal, then:  \i e0-readonly-check.sql   (or paste the whole file).
-- Copy the output back to Claude. Do not paste the PSQL command itself: it contains the password.

BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '60s';

\echo '== 1. Counts =='
SELECT
  (SELECT count(*) FROM documents WHERE deleted_at IS NULL)     AS active_documents,
  (SELECT count(*) FROM documents WHERE deleted_at IS NOT NULL) AS deleted_documents,
  (SELECT count(*) FROM document_keys)                          AS wrapped_keys,
  (SELECT count(*) FROM stored_objects)                         AS stored_objects,
  (SELECT count(*) FROM document_claims)                        AS field_values,
  (SELECT count(*) FROM credentials)                            AS credentials,
  (SELECT count(*) FROM sharing_links)                          AS links;

\echo '== 2. Every active document has a key and a stored object (all should be 0) =='
SELECT
  (SELECT count(*) FROM documents d WHERE d.deleted_at IS NULL
     AND NOT EXISTS (SELECT 1 FROM document_keys k WHERE k.document_id = d.id))     AS active_without_key,
  (SELECT count(*) FROM documents d WHERE d.deleted_at IS NULL
     AND NOT EXISTS (SELECT 1 FROM stored_objects o WHERE o.key = d.storage_key))   AS active_without_object,
  (SELECT count(*) FROM documents d WHERE d.deleted_at IS NOT NULL
     AND EXISTS (SELECT 1 FROM document_keys k WHERE k.document_id = d.id))         AS deleted_with_key_left,
  (SELECT count(*) FROM documents d WHERE d.deleted_at IS NOT NULL
     AND EXISTS (SELECT 1 FROM stored_objects o WHERE o.key = d.storage_key))       AS deleted_with_object_left,
  (SELECT count(*) FROM stored_objects o
     WHERE NOT EXISTS (SELECT 1 FROM documents d WHERE d.storage_key = o.key))      AS orphan_objects;

\echo '== 3. AES-256-GCM shapes (bad_* should all be 0) =='
SELECT
  count(*) FILTER (WHERE length(enc_iv)  <> 12) AS bad_file_iv,
  count(*) FILTER (WHERE length(enc_tag) <> 16) AS bad_file_tag,
  count(*) - count(DISTINCT enc_iv)             AS repeated_file_ivs
FROM documents;
SELECT
  count(*) FILTER (WHERE length(wrapped_dek) <> 32) AS bad_wrapped_key_length,
  count(*) FILTER (WHERE length(wrap_iv)     <> 12) AS bad_wrap_iv,
  count(*) FILTER (WHERE length(wrap_tag)    <> 16) AS bad_wrap_tag
FROM document_keys;
SELECT kek_version, count(*) AS keys FROM document_keys GROUP BY kek_version ORDER BY kek_version;

\echo '== 4. Stored files look like ciphertext, not like PDF/PNG/JPEG (all should be 0) =='
SELECT
  count(*) FILTER (WHERE substr(o.data, 1, 4) = '\x25504446'::bytea) AS starts_like_pdf,
  count(*) FILTER (WHERE substr(o.data, 1, 4) = '\x89504e47'::bytea) AS starts_like_png,
  count(*) FILTER (WHERE substr(o.data, 1, 3) = '\xffd8ff'::bytea)   AS starts_like_jpeg,
  count(*) FILTER (WHERE position('endobj'::bytea  IN o.data) > 0)   AS contains_pdf_marker,
  count(*) FILTER (WHERE position('%%EOF'::bytea   IN o.data) > 0)   AS contains_pdf_eof,
  count(*) FILTER (WHERE length(o.data) <> d.size_bytes)             AS size_mismatch
FROM stored_objects o JOIN documents d ON d.storage_key = o.key
WHERE d.deleted_at IS NULL;

\echo '== 5. Randomness: distinct byte values in the first 4 KB of each file (ciphertext ~ 240-256) =='
SELECT min(distinct_bytes) AS min_distinct, round(avg(distinct_bytes)) AS avg_distinct, count(*) AS files_checked
FROM (
  SELECT (SELECT count(DISTINCT get_byte(o.data, i))
            FROM generate_series(0, least(length(o.data), 4096) - 1) AS i) AS distinct_bytes
  FROM stored_objects o JOIN documents d ON d.storage_key = o.key
  WHERE d.deleted_at IS NULL AND length(o.data) >= 4096
) s;

\echo '== 6. Field values, credentials and link copies are sealed (bad_* / printable_* should be 0) =='
SELECT
  count(*) FILTER (WHERE length(value_encrypted) < 28) AS bad_value_length,
  count(*) FILTER (WHERE length(value_encrypted) >= 28 AND NOT EXISTS (
     SELECT 1 FROM generate_series(0, 27) i WHERE get_byte(value_encrypted, i) NOT BETWEEN 32 AND 126
  )) AS printable_values
FROM document_claims;
SELECT count(*) FILTER (WHERE length(credential_encrypted) < 28) AS bad_credential_length FROM credentials;
SELECT count(*) FILTER (WHERE length(token_encrypted) < 28)      AS bad_token_copy_length FROM sharing_links;

\echo '== 7. Known plaintext metadata (expected > 0 today; E3/E4/E5 bring these to 0) =='
SELECT
  (SELECT count(*) FROM documents WHERE length(title) > 0 AND deleted_at IS NULL) AS titles_in_clear,
  (SELECT count(*) FROM document_claims WHERE length(label) > 0)                 AS field_labels_in_clear,
  (SELECT count(*) FROM sharing_links WHERE length(recipient_label) > 0)         AS recipient_labels_in_clear,
  (SELECT count(*) FROM documents WHERE length(plaintext_sha256) = 64)           AS unkeyed_file_hashes,
  (SELECT count(*) FROM security_events WHERE metadata ? 'title')                AS log_rows_with_title,
  (SELECT count(*) FROM documents d WHERE d.deleted_at IS NOT NULL AND EXISTS (
     SELECT 1 FROM security_events e WHERE e.document_id = d.id AND e.metadata ? 'title'))
                                                                                  AS deleted_docs_title_in_logs;

ROLLBACK;
