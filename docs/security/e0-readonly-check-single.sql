-- E0 (single-statement version) for browser SQL tools: Render's pgAdmin app or the
-- Render MCP read-only query tool. Same checks as e0-readonly-check.sql.
--
-- It is ONE SELECT statement: it cannot change data. It also reports
-- transaction_read_only so the output itself proves the session was read-only.
-- It returns only counts and PASS / CHECK / KNOWN GAP answers: no contents, keys,
-- titles, names, emails or ids.
--
-- pgAdmin: paste the line below AND the SELECT together, run, then run  ROLLBACK;
--   BEGIN TRANSACTION READ ONLY;
WITH
active AS (SELECT * FROM documents WHERE deleted_at IS NULL),
deleted AS (SELECT * FROM documents WHERE deleted_at IS NOT NULL),
files AS (
  SELECT o.data, d.size_bytes
  FROM stored_objects o JOIN active d ON d.storage_key = o.key
),
entropy AS (
  SELECT (SELECT count(DISTINCT get_byte(f.data, i))
            FROM generate_series(0, least(length(f.data), 4096) - 1) AS i) AS distinct_bytes
  FROM files f WHERE length(f.data) >= 4096
),
checks(n, area, check_name, value, expect) AS (
  VALUES
  (1,  'session',  'transaction_read_only (must be on)',          CASE WHEN current_setting('transaction_read_only') = 'on' THEN 1 ELSE 0 END::bigint, 'one'),
  (2,  'counts',   'active documents',                            (SELECT count(*) FROM active), 'info'),
  (3,  'counts',   'deleted documents',                           (SELECT count(*) FROM deleted), 'info'),
  (4,  'counts',   'wrapped keys',                                (SELECT count(*) FROM document_keys), 'info'),
  (5,  'counts',   'stored objects',                              (SELECT count(*) FROM stored_objects), 'info'),
  (6,  'counts',   'field values',                                (SELECT count(*) FROM document_claims), 'info'),
  (7,  'counts',   'credentials',                                 (SELECT count(*) FROM credentials), 'info'),
  (8,  'counts',   'sharing links',                               (SELECT count(*) FROM sharing_links), 'info'),
  (10, 'keys',     'active documents without a wrapped key',      (SELECT count(*) FROM active d WHERE NOT EXISTS (SELECT 1 FROM document_keys k WHERE k.document_id = d.id)), 'zero'),
  (11, 'keys',     'active documents without a stored object',    (SELECT count(*) FROM active d WHERE NOT EXISTS (SELECT 1 FROM stored_objects o WHERE o.key = d.storage_key)), 'zero'),
  (12, 'keys',     'deleted documents with a key left',           (SELECT count(*) FROM deleted d WHERE EXISTS (SELECT 1 FROM document_keys k WHERE k.document_id = d.id)), 'zero'),
  (13, 'keys',     'deleted documents with ciphertext left',      (SELECT count(*) FROM deleted d WHERE EXISTS (SELECT 1 FROM stored_objects o WHERE o.key = d.storage_key)), 'zero'),
  (14, 'keys',     'stored objects with no document (orphans)',   (SELECT count(*) FROM stored_objects o WHERE NOT EXISTS (SELECT 1 FROM documents d WHERE d.storage_key = o.key)), 'zero'),
  (20, 'gcm',      'file IVs not 12 bytes',                       (SELECT count(*) FROM documents WHERE length(enc_iv) <> 12), 'zero'),
  (21, 'gcm',      'file tags not 16 bytes',                      (SELECT count(*) FROM documents WHERE length(enc_tag) <> 16), 'zero'),
  (22, 'gcm',      'repeated file IVs',                           (SELECT count(*) - count(DISTINCT enc_iv) FROM documents), 'zero'),
  (23, 'gcm',      'wrapped keys not 32 bytes',                   (SELECT count(*) FROM document_keys WHERE length(wrapped_dek) <> 32), 'zero'),
  (24, 'gcm',      'key-wrap IVs not 12 / tags not 16 bytes',     (SELECT count(*) FROM document_keys WHERE length(wrap_iv) <> 12 OR length(wrap_tag) <> 16), 'zero'),
  (25, 'gcm',      'distinct master-key versions in use',         (SELECT count(DISTINCT kek_version) FROM document_keys), 'info'),
  (30, 'at rest',  'stored files starting like a PDF',            (SELECT count(*) FROM files WHERE substr(data, 1, 4) = '\x25504446'::bytea), 'zero'),
  (31, 'at rest',  'stored files starting like a PNG',            (SELECT count(*) FROM files WHERE substr(data, 1, 4) = '\x89504e47'::bytea), 'zero'),
  (32, 'at rest',  'stored files starting like a JPEG',           (SELECT count(*) FROM files WHERE substr(data, 1, 3) = '\xffd8ff'::bytea), 'zero'),
  (33, 'at rest',  'stored files containing "endobj"',            (SELECT count(*) FROM files WHERE position('endobj'::bytea IN data) > 0), 'zero'),
  (34, 'at rest',  'stored files containing "%%EOF"',             (SELECT count(*) FROM files WHERE position('%%EOF'::bytea IN data) > 0), 'zero'),
  (35, 'at rest',  'stored size differs from original size',      (SELECT count(*) FROM files WHERE length(data) <> size_bytes), 'zero'),
  (36, 'at rest',  'lowest distinct bytes in first 4 KB (>= 200)',(SELECT coalesce(min(distinct_bytes), 256) FROM entropy), 'min200'),
  (40, 'fields',   'field values shorter than iv+tag (28 bytes)', (SELECT count(*) FROM document_claims WHERE length(value_encrypted) < 28), 'zero'),
  (41, 'fields',   'field values that look like readable text',   (SELECT count(*) FROM document_claims c WHERE length(c.value_encrypted) >= 28 AND NOT EXISTS (
                                                                     SELECT 1 FROM generate_series(0, 27) i WHERE get_byte(c.value_encrypted, i) NOT BETWEEN 32 AND 126)), 'zero'),
  (42, 'fields',   'credentials shorter than 28 bytes',           (SELECT count(*) FROM credentials WHERE length(credential_encrypted) < 28), 'zero'),
  (43, 'fields',   'link copies shorter than 28 bytes',           (SELECT count(*) FROM sharing_links WHERE length(token_encrypted) < 28), 'zero'),
  (50, 'metadata', 'titles stored in clear',                      (SELECT count(*) FROM active WHERE length(title) > 0), 'gap'),
  (51, 'metadata', 'field labels stored in clear',                (SELECT count(*) FROM document_claims WHERE length(label) > 0), 'gap'),
  (52, 'metadata', 'recipient names stored in clear',             (SELECT count(*) FROM sharing_links WHERE length(recipient_label) > 0), 'gap'),
  (53, 'metadata', 'unkeyed SHA-256 file hashes',                 (SELECT count(*) FROM documents WHERE length(plaintext_sha256) = 64), 'gap'),
  (54, 'metadata', 'log rows containing a title',                 (SELECT count(*) FROM security_events WHERE metadata ? 'title'), 'gap'),
  (55, 'metadata', 'deleted documents whose title is still in logs', (SELECT count(*) FROM deleted d WHERE EXISTS (
                                                                     SELECT 1 FROM security_events e WHERE e.document_id = d.id AND e.metadata ? 'title')), 'gap')
)
SELECT area, check_name, value,
  CASE expect
    WHEN 'info'   THEN 'INFO'
    WHEN 'gap'    THEN CASE WHEN value = 0 THEN 'PASS' ELSE 'KNOWN GAP (E3-E5)' END
    WHEN 'zero'   THEN CASE WHEN value = 0 THEN 'PASS' ELSE 'CHECK' END
    WHEN 'one'    THEN CASE WHEN value = 1 THEN 'PASS' ELSE 'STOP: not read-only' END
    WHEN 'min200' THEN CASE WHEN value >= 200 THEN 'PASS' ELSE 'CHECK' END
  END AS result
FROM checks
ORDER BY n;
