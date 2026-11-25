-- Repair amounts imported by the Livin email parser v1/v2.
--
-- Those parser generations returned whole rupiah ("Rp 25.000" -> 25000) while every other write
-- path (manual entry, Android client, API contract) stores minor units, i.e. 1/100 IDR. Imported
-- rows therefore displayed 100x smaller than the transaction printed in the email. New rows are
-- parsed by gmail-livin-v3, which returns minor units. Every pre-existing EMAIL row came from the
-- same parser, so the only correct repair is a one-time 100x scaling.
--
-- The bound keeps the UPDATE inside the amount CHECK even on an unexpected outlier, and the
-- source/parser filter leaves MANUAL rows and non-email sources untouched.
UPDATE transactions
   SET amount_minor = amount_minor * 100
 WHERE source = 'EMAIL'
   AND parser_version IN ('gmail-livin-v1', 'gmail-livin-v2')
   AND amount_minor BETWEEN 1 AND 1000000000000000 / 100;

-- Summary/analysis caches are keyed by the owner/month revision, so changed amounts must bump it;
-- otherwise a cached summary for the same revision would keep serving the old total.
INSERT INTO month_revisions (owner_id, month_id, revision, updated_at)
SELECT DISTINCT owner_id, month_id, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM transactions
 WHERE source = 'EMAIL'
   AND parser_version IN ('gmail-livin-v1', 'gmail-livin-v2')
ON CONFLICT(owner_id, month_id) DO UPDATE SET
  revision = month_revisions.revision + 1,
  updated_at = excluded.updated_at;
