# Runtime smoke build final backend — 24 November 2026

Dijalankan pada HEAD `f1625b5` (`integration/2026-11-24`), binary hasil `go build` dari
`./cmd/api`, DB SQLite baru di `/tmp`, port 18141/18142. Tidak menyentuh DB/pot owner dan
tidak memakai kredensial Google. Tujuan: membuktikan guard retensi P2 bekerja pada **runtime**,
bukan hanya di unit test.

## Setup

- `APP_ENV=development`, `DATABASE_URL=file:/tmp/pam-audit-smoke-<pid>.db`,
  `INTERNAL_SWEEP_TOKEN=smoke-token-123`, Gmail disabled (default).
- Registrasi akun sintetis `audit.smoke@example.test` (bukan data pemilik).
- Baris kedaluwarsa dibuat dengan menggeser `event_at_ms`/`month_id` langsung di DB setelah
  dibuat lewat API, sehingga jalur baca/ubah nyata yang diuji.

## Hasil ringkas

| Pemeriksaan | Hasil |
|---|---|
| Migrasi DB baru | 19 baris, versi 1–19 |
| `/healthz`, `/readyz` | 200, 200 |
| Guard tanpa token | `/v1/retention` 401; sweep tanpa/salah token 401 |
| `GET /v1/retention` | 200, jendela `2025-11`..`2026-11`, 12 bulan, `Asia/Jakarta` |
| `GET /v1/gmail/status` saat Gmail disabled | 503 `gmail_disabled` |
| Guard periode kedaluwarsa (transaksi list/create, ringkasan GET/PUT, analisis, import-job create) | 400 `outside_retention` + envelope lengkap |
| Lampiran kedaluwarsa `GET`/`PATCH` by-id | **400 `outside_retention`** (sebelum perbaikan 200) |
| `GET /v1/attachments?transactionId=<kedaluwarsa>` | 400 `outside_retention` |
| `GET /v1/attachments` tanpa filter | 200 dengan `items=0` (baris kedaluwarsa di-clamp, bukan bocor) |
| `GET /v1/import-jobs/{kedaluwarsa}` | **400 `outside_retention`** (sebelum perbaikan 200) |
| Sweep report-only | 200 `REPORT_ONLY`, tidak menghapus, menulis 1 baris audit |
| Restart dengan `RETENTION_DELETE_ENABLED=true` | sweep otomatis `DELETE`; transaksi/lampiran kedaluwarsa terhapus, baris baru tetap |
| Sweep delete lewat endpoint | tanpa `confirm` 400 `confirmation_required`; dengan konfirmasi 200 `DELETE` |
| Audit | `REPORT_ONLY`, `DELETE`, `DELETE` (satu per run yang selesai) |

## Output mentah

```text
### db=/tmp/pam-audit-smoke-88878.db ports=18141/18142
health=200 ready=200
migrations=[(19, 1, 19)]
retention no-jwt=401
sweep no-token=401 wrong-token=401
register=201
GET /v1/retention=200 keys=['endMonthId', 'months', 'startMonthId', 'timezone', 'windowEnd', 'windowStart'] window=2025-11-24T00:00:00+07:00..2026-11-24T15:30:13.98163+07:00 startMonth=2025-11
GET /v1/gmail/status (Gmail disabled)=503 body={'code': 'gmail_disabled', 'message': 'Gmail integration is not enabled', 'retryable': False, 'correlationId': 'req_9e3f81042581256910e9d4ac8b5add35'}
POST tx expired=400 code=outside_retention envelope=['endMonthId', 'months', 'startMonthId', 'timezone', 'windowEnd', 'windowStart']
GET tx list expired month=400 code=outside_retention
GET summary expired=400 code=outside_retention
PUT summary expired=400 code=outside_retention
GET analysis expired=400 code=outside_retention
consent GMAIL_READ=201
POST import-job current=201 id=job_d63566fb58da39e8b3633bcae7bace7d
POST import-job expired=400 code=outside_retention
POST tx recent=201 id=tx_94fbb6cf4d114df118943dcc0abb4268
POST attachment=201 id=att_76a8ef5833cf580924ab76ea35c8a227 body={'attributes': {}, 'createdAt': '2026-11-24T08:30:13.989357Z', 'deviceRef': 'dev_smoke', 'fileName': 'nota.pdf', 'id': 'att_76a8ef5833cf580924ab76ea35c8a227', 'localFileId': 'lf_smoke_1', 'mimeType': 'application/pdf', 'revision': 0, 'sha256': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'sizeBytes': 1000, 'storageRef': 'attachments/nota.pdf', 'transactionId': 'tx_94fbb6cf4d114df118943dcc0abb4268', 'updatedAt': '2026-11-24T08:30:13.989357Z'}
seeded expired: tx=tx_94fbb6cf4d114df118943dcc0abb4268 att=att_76a8ef5833cf580924ab76ea35c8a227 job=job_d63566fb58da39e8b3633bcae7bace7d
-- direct object reads of expired rows
GET tx expired=400 code=outside_retention
GET attachment expired=400 (200 => no retention guard)
PATCH attachment expired=400 (200 => no retention guard)
GET attachments?transactionId expired=400 code=outside_retention
GET attachments (no filter)=200 items=0 (200 with expired row => bypass)
GET import-job expired=400 (200 => no retention guard) month=None
-- report-only sweep
audit before=[(0,)]
POST sweep report=200 mode=REPORT_ONLY deleted=False counts={'transactions': 1, 'attachments': 1, 'summaries': 0, 'analyses': 0, 'categoryJobs': 0, 'categoryCache': 0, 'importJobs': 1, 'importBatches': 0, 'importSkipped': 0}
audit after=[(1,)] rows remaining: tx=[(1,)] att=[(1,)] job=[(1,)]
-- restart with RETENTION_DELETE_ENABLED=true (worker performs one DELETE sweep on start)
audit modes=[('REPORT_ONLY',), ('DELETE',)]
after startup delete: tx=[(0,)] att=[(0,)]
POST tx recent on delete-server=201 id=tx_4897594de8073147a0ae6772d5a7a3fc
sweep delete without confirm=400 code=confirmation_required
sweep delete with confirm=200 mode=DELETE deleted=True counts={'transactions': 1, 'attachments': 0, 'summaries': 0, 'analyses': 0, 'categoryJobs': 0, 'categoryCache': 0, 'importJobs': 0, 'importBatches': 0, 'importSkipped': 0}
tx2 remaining=[(0,)] audit rows=[('REPORT_ONLY',), ('DELETE',), ('DELETE',)]
```

Catatan: skrip smoke ini menandai teks "(200 => no retention guard)" sebagai label lama dari
audit sebelumnya; nilai status yang tercetak (400) adalah hasil sebenarnya pada build final.
