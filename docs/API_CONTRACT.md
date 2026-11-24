# PAM Backend — API Contract v0.4 (review draft)

**Extension target v0.5:** [CR-004](changes/CR_004_AZURE_LLM_CATEGORIZATION.md) menambah
purpose `AI_CATEGORIZATION` dan typed classification jobs. Ini bukan endpoint yang sudah ada.
SE harus merinci request/job/readback/migration sesuai FR-66…71 sebelum mengaktifkan flag.
Jangan melebarkan payload aggregate `Analyze` atau memakai consent AI lama sebagai izin merchant.
Provider input target: sanitized business merchant ≤120 chars, verified direction/method,
built-in category codes dan taxonomy version. Output: categoryCode, needsReview, reasonCode.
Backend membangun input dari owner record; no raw email/ID, account/card, nominal/tanggal,
personal counterparty, notes/attributes/custom labels. Category apply memerlukan owner+expected
revision dan perlindungan USER override. Cloud provider setup: [runbook](AZURE_CLASSIFIER_SETUP.md).

Status: **DRAFT REVIEW**, 21 November 2026. Cloud database gratis disetujui pemilik; sign-off
paket v0.4 belum tercatat. Kontrak ini adalah target C1/C2, bukan deskripsi kode v0.3 yang sedang
berjalan. Sumber requirement: [`12_SRS_v0.4_REVIEW.md`](12_SRS_v0.4_REVIEW.md) FR-02/35/52/56–63,
DR-02/04/05, NFR-15/16/19/21/22/23.

**Implementasi target:** layanan Go di `backend-go/` (Go 1.27.4, `net/http`, `database/sql`,
driver libSQL remote + SQLite lokal untuk tes). `backend/` Node adalah referensi perilaku dan jalur
rollback; lihat [`13_GO_BACKEND_MIGRATION.md`](13_GO_BACKEND_MIGRATION.md). Migrasi SQL dimiliki
oleh Go untuk database baru.
**Base:** `https://<api>/v1` (lokal `http://127.0.0.1:8080`). JSON UTF-8. Waktu ISO-8601 UTC.
Bulan `YYYY-MM` dalam **Asia/Jakarta**. Nominal selalu **integer minor IDR** (1/100 rupiah).

---

## 1. Prinsip yang tidak boleh dilanggar

1. **Owner dari sesi.** `owner_id` tidak pernah diterima dari body/query. Setiap query memfilter
   owner; admin tidak dapat membaca data keuangan pengguna lain (FR-02).
2. **Atomisitas.** Operasi yang menyentuh lebih dari satu tabel berjalan dalam satu transaksi
   tulis libSQL. Gagal di tengah = tidak ada perubahan.
3. **Idempotensi.** Create manual dan batch impor memakai idempotency key per owner. Key sama +
   body sama mengembalikan hasil tersimpan; key sama + body berbeda → `409 idempotency_conflict`.
4. **Revisi.** Setiap perubahan transaksi menaikkan `month_revisions.revision`; ringkasan/analisis
   membandingkan `inputRevision`. Update memakai `If-Match` dan gagal `409 revision_conflict` bila
   versi berubah.
5. **Batas payload.** Body ≤256 KB, batch ≤100 kandidat, amount ≤`1_000_000_000_000_000` minor,
   `Number.isSafeInteger` wajib.
6. **Tanpa rahasia di log.** Tidak ada body, email, merchant, nominal, token, ciphertext, atau
   path file di log. `correlationId` selalu ada.

---

## 2. Auth: JWT access + refresh rotation

### 2.1 Register

```http
POST /v1/accounts
{ "email": "a@example.test", "password": "8..200 chars", "displayName": "A", "inviteCode": "..." }
```
`inviteCode` **wajib untuk semua registrasi**, termasuk bila body juga membawa `invitationToken`:
server memeriksa gate `inviteCode` lebih dulu, sebelum memilih jalur undangan. `invitationToken`
adalah jalur legacy penerimaan undangan admin yang sudah diterbitkan; bila valid (belum dipakai,
belum kedaluwarsa, email cocok) role diambil dari undangan, bukan dari body, dan bila tidak
dikirim akun selalu dibuat sebagai `USER`. API pembuatan undangan baru sudah pensiun (404), jadi
token yang beredar hanyalah undangan lama; keputusan produk OI-28 tetap terbuka (lihat §2.6).
`201 { userId, email, displayName, role: "USER"|"ADMIN" }`. Duplicate email → `409 conflict`;
kode undangan kosong/salah → `403 forbidden` (`invalid_invite`, token tidak diproses); token tidak
valid/email tidak cocok → `400 invalid_invitation`; token terpakai → `409 invitation_used`; token
kedaluwarsa → `410 invitation_expired`. Server membuat `account_keys` (kunci fingerprint) dalam
transaksi yang sama.

### 2.2 Login

```http
POST /v1/sessions
{ "email": "...", "password": "..." }
```
`201`:
```json
{
  "accessToken": "<JWT>",
  "accessExpiresAt": "2026-11-21T12:15:00Z",
  "refreshToken": "<opaque 32-byte base64url>",
  "refreshExpiresAt": "2026-12-21T12:00:00Z",
  "user": { "id": "u_...", "email": "...", "displayName": "A", "role": "USER" }
}
```
Access JWT (HS256, `JWT_SECRET` ≥32 byte):
`iss=pam-api`, `aud=pam-android`, `sub=<owner_id>`, `sid=<auth_sessions.id>`,
`role=USER|ADMIN`, `ver=<users.auth_version>`, `iat`, `exp` (≤15 menit), `jti`.

Setiap request terautentikasi memverifikasi signature, `iss`, `aud`, `exp`/`nbf` (toleransi 60 dtk),
lalu memuat `auth_sessions` dan `users`. Tolak `401 session_stale` bila sesi dicabut/kedaluwarsa,
`sub` tidak cocok, `ver` berbeda, status bukan `ACTIVE`, atau role klaim berbeda dari DB.
Perubahan role/status menaikkan `auth_version` dan mencabut sesi dalam transaksi yang sama.

Refresh token: 32 byte opaque; server hanya menyimpan `sha256(token + REFRESH_PEPPER)`; TTL 30 hari.

### 2.3 Refresh (rotasi atomik)

```http
POST /v1/sessions/refresh
{ "refreshToken": "..." }
```
`200` = pasangan access + refresh baru. Implementasi wajib dalam satu transaksi:
1. cari `refresh_tokens.token_hash`, belum revoked/expired;
2. **insert replacement lebih dulu** (karena `replaced_by_id` adalah foreign key);
3. revoke token lama (`revoked_reason='rotated'`, `replaced_by_id=<baru>`);
4. kembalikan pasangan baru.

Token lama yang dipakai lagi setelah rotasi = replay: revoke **seluruh keluarga** dan `401
refresh_reused`. Tidak ada grace period yang mengembalikan token baru yang sama.

### 2.4 Logout / revoke

```http
DELETE /v1/sessions      Authorization: Bearer <access>
```
`204`; revoke `auth_sessions` + semua `refresh_tokens` keluarga itu. Access token lama langsung
ditolak karena sesi dicabut (bukan menunggu TTL).

### 2.5 Klien

- Satu **single-flight refresh** untuk semua request paralel; tidak ada dua refresh bersamaan.
- Setiap request diulang **maksimal sekali** setelah refresh berhasil.
- Refresh yang gagal/ambigu tidak diulang buta. Klien menghapus token, mempertahankan isian form
  yang belum terkirim bila aman, dan masuk ke layar pemulihan sesi (FR-62).
- Access/refresh disimpan dengan Keystore; `Authorization` tidak pernah dicatat.

### 2.6 Provisioning admin dan OI-28 (CR-008)

CR-008 memensiunkan administrasi pengguna dari cakupan produk. Build target kini hanya punya satu
peran aplikasi, `USER`; `POST /v1/admin/invitations` dan seluruh `/v1/admin/*` tidak lagi terdaftar
(404). Penerimaan undangan yang sudah ada tetap dipertahankan: `POST /v1/accounts` masih menerima
`invitationToken` lama **asalkan gate `inviteCode` terpenuhi**, dan role ditentukan oleh token,
bukan body. Tidak ada pendaftaran publik role tinggi, tidak ada pembuatan undangan baru lewat API,
dan tidak ada auto-create akun dari Google SSO.

**Dampak OI-28 (terbuka):** jalur pembuatan undangan admin hilang, sehingga akun `ADMIN` baru hanya
dapat dibuat lewat CLI/ops `pam-admin -promote <email>` (akun harus sudah terdaftar; CLI idempoten
dan menulis audit). Pedoman akademik
D.2 (peran) perlu dipetakan ulang ke satu peran + isolasi data; keputusan produk lanjutan menunggu
pemilik dan tidak mengubah kontrak onboarding saat ini.

---

## 3. Error, ownership dan forbidden

Semua error:
```json
{ "code": "revision_conflict", "message": "…", "retryable": false, "correlationId": "…" }
```

| HTTP | `code` | Kapan |
|---|---|---|
| 400 | `invalid_request`, `outside_retention` | skema/rentang tidak valid |
| 401 | `unauthorized`, `session_stale`, `refresh_invalid`, `refresh_reused` | auth |
| 403 | `forbidden`, `consent_required`, `builtin_category` | hak/consent |
| 404 | `not_found` | objek tidak ada **atau** milik owner lain |
| 409 | `conflict`, `idempotency_conflict`, `revision_conflict`, `category_in_use`, `last_admin`, `deletion_in_progress` | konflik |
| 413 | `payload_too_large` | body/batch/file metadata |
| 415 | `unsupported_media_type` | MIME lampiran |
| 422 | `validation_failed`, `invalid_analysis_output` | isi bisnis |
| 429 | `rate_limited`, `daily_ceiling_reached` | kuota |
| 502 | `provider_unavailable` | LLM |
| 503 | `database_unavailable` | DB tidak terjangkau — retryable |

Objek milik owner lain selalu `404` (bukan `403`) agar tidak menjadi oracle. `consent_required`
hanya untuk operasi AI/impor yang memerlukan consent.

---

## 4. Tabel endpoint

| Method | Path | Auth | Kewajiban |
|---|---|---|---|
| GET | `/healthz` | — | liveness |
| POST | `/v1/accounts` | — | FR-51/58 register |
| POST | `/v1/sessions` | — | FR-57 login |
| POST | `/v1/sessions/refresh` | refresh | FR-57 rotasi |
| DELETE | `/v1/sessions` | JWT | FR-05/57 logout |
| GET | `/v1/me` | JWT | profil, role, consent, sesi |
| GET | `/v1/fingerprint-key` | JWT | kunci HMAC per akun (DR-02) |
| GET/POST | `/v1/consents` | JWT | FR-03 ledger |
| GET | `/v1/transactions` | JWT | list/filter/search FR-27/60 |
| POST | `/v1/transactions` | JWT | create manual FR-60 |
| GET | `/v1/transactions/{id}` | JWT | detail owner |
| PATCH | `/v1/transactions/{id}` | JWT | update + `If-Match` |
| DELETE | `/v1/transactions/{id}` | JWT | soft delete + lampiran |
| GET | `/v1/categories` | JWT | list/search |
| POST | `/v1/categories` | JWT | create user category |
| GET | `/v1/categories/{id}` | JWT | detail |
| PATCH | `/v1/categories/{id}` | JWT | label/warna/atribut |
| DELETE | `/v1/categories/{id}?reassignTo=` | JWT | reassign + soft delete |
| POST | `/v1/import-jobs` | JWT | buat job |
| GET | `/v1/import-jobs/{id}` | JWT | status job |
| POST | `/v1/import-jobs/{id}/batches` | JWT | batch atomik/idempoten |
| PATCH | `/v1/import-jobs/{id}` | JWT | finalisasi state |
| GET | `/v1/summaries/{monthId}` | JWT | ringkasan server-side |
| POST | `/v1/analyses` | JWT | FR-34…41/50 |
| GET | `/v1/analyses/{monthId}` | JWT | analisis tersimpan |
| POST/GET | `/v1/deletion-requests` | JWT | FR-47/48 |
| POST | `/v1/gmail/connect/start` | JWT | mulai OAuth Gmail (state sekali pakai) |
| GET | `/v1/gmail/connect/callback` | — (state) | tukar code → 302 deep link |
| GET | `/v1/gmail/status` | JWT | status koneksi (email masked) |
| POST | `/v1/gmail/disconnect` | JWT | stop watch + revoke + hapus kredensial |
| POST | `/v1/internal/gmail/push` | OIDC Google | terima Pub/Sub push + ACK idempoten |
| GET | `/v1/retention` | JWT | metadata jendela retensi setahun |
| POST | `/v1/internal/retention-sweep` | `x-internal-token` | sweep report-only/delete |

`monthId` = `YYYY-MM` Asia/Jakarta.

---

## 5. Transaksi

### 5.1 Create

`Idempotency-Key` is **required** for manual create (1..200 printable characters). The server stores
the key, normalized request hash and result id in `http_idempotency` in the same transaction as the
row. Same key + same body → the original row with `200` and `Idempotency-Replayed: true`; same key +
different body → `409 idempotency_conflict`; a retry after soft delete returns the tombstone
(`deletedAt`) and never resurrects the row. Parallel writers are serialized by the unique key.

```http
POST /v1/transactions
Idempotency-Key: <uuid>
{
  "direction": "DEBIT",
  "amountMinor": 4500000,
  "currency": "IDR",
  "eventAt": "2026-02-03T01:12:44Z",
  "categoryId": "cat_...",
  "description": "QRIS",
  "merchantLabel": "Kopi …",
  "note": null,
  "attributes": { "tags": ["makan"] },
  "source": "MANUAL",
  "isInternalTransfer": false,
  "linkedRefundOf": null
}
```
Server menurunkan `monthId` dari `eventAt` di Asia/Jakarta, memvalidasi amount/IDR/rentang retensi
(12 bulan), lalu menyimpan field sensitif (`description`, `merchantLabel`, `note`, `attributes`)
sebagai satu JSON AES-GCM. Respons `201`:
`{ id, revision: 0, monthId, direction, amountMinor, currency, eventAt, categoryId, source,
  createdAt, updatedAt }`.

### 5.2 Read/list/search

`GET /v1/transactions?month=2026-02&categoryId=&direction=&source=&cursor=&limit=50&q=`
- `limit` default 50, max 100; `cursor` opaque = `(event_at_ms, id)`.
- Tanpa `q`: query terindeks `(owner_id, month_id, deleted_at, event_at_ms DESC, id)`.
- Dengan `q`: wajib `month` (atau `from`/`to` ≤31 hari); backend mendekripsi dan memindai maksimum
  2.000 baris, mengembalikan `items`, `nextCursor`, dan `search:{scanned,truncated}`. Tidak ada
  `LIKE` pada ciphertext.
- Soft-deleted tidak pernah muncul.

### 5.3 Update / delete

`PATCH` body `{ categoryId?, description?, merchantLabel?, note?, attributes?, isInternalTransfer?,
linkedRefundOf? }` + `If-Match: "<revision>"`. Kategori harus milik owner dan aktif. Perubahan
kategori mencatat `categoryOrigin=USER`. `409 revision_conflict` bila versi berubah.

`DELETE` soft-delete baris + metadata lampiran terkait dalam satu transaksi, menaikkan revisi
bulan. `204`. Fingerprint tetap reserved: impor ulang tidak menghidupkan kembali baris yang sengaja
dihapus (dihitung duplikat).

---

## 6. Kategori

`GET /v1/categories?q=&kind=&includeDeleted=false` — label didekripsi; kategori bawaan
(`isBuiltin=true`) tidak dapat dihapus.

`POST { code?, label, kind, color?, attributes? }` → `201`. `code` dibuat server bila kosong.
`PATCH { label?, color?, attributes?, kind? }` + `If-Match`. `DELETE ?reassignTo=<categoryId>`:
- tanpa `reassignTo` dan masih direferensikan → `409 category_in_use`;
- dengan `reassignTo` → pindahkan semua transaksi aktif + `budget_limits` lalu soft-delete kategori
  dalam satu transaksi;
- kategori bawaan → `403 builtin_category`.

Kategori pengguna boleh memiliki `attributes` key–value; label/atribut disegel dan tidak pernah
dikirim ke model AI.

---

## 7. Impor batch

### 7.1 Buat job

`POST /v1/import-jobs { "monthId": "2026-02", "templateVersion": "v1" }` → `201
{ id, state: "CREATED", ... }`.

### 7.2 Kirim batch

`POST /v1/import-jobs/{id}/batches`
```json
{
  "batchKey": "page-1",
  "pageOrdinal": 0,
  "candidates": [
    {
      "fingerprint": "32 hex",
      "status": "PARSED",
      "direction": "DEBIT",
      "amountMinor": 17500000,
      "eventAt": "2026-02-19T04:10:00Z",
      "categoryId": "cat_...",
      "parserVersion": "livin-bill-payment/v1",
      "confidence": 0.9,
      "description": "Pembayaran",
      "merchantLabel": "Indomaret",
      "attributes": {}
    },
    { "fingerprint": "32 hex", "status": "UNRESOLVED", "reason": "FAILED_PAYMENT" }
  ]
}
```
- ≤100 kandidat; `batchKey` unik per job.
- Dalam **satu transaksi**: validasi semua, insert transaksi baru dengan
  `INSERT ... ON CONFLICT(owner_id,fingerprint) DO NOTHING`, catat `import_skipped` (hanya reason
  code), update counter job, simpan `import_batches` + `request_hash`, naikkan `month_revisions`
  satu kali.
- Batch key sama + hash sama → `200` dengan counts tersimpan; hash berbeda → `409`.
- Kandidat `UNRESOLVED` tidak menyimpan nominal/merchant/body.
- Respons `200 { batchKey, matched, imported, duplicates, skipped, unresolved, inputRevision }`.

### 7.3 Finalisasi

`PATCH /v1/import-jobs/{id} { "state": "COMPLETE|PARTIAL|FAILED|EMPTY|PERMISSION_REQUIRED",
"errorCode": null }` → `200` job. Transisi state invalid → `409`. `matched` dihitung server dari
kandidat yang diterima; UI tidak boleh mengarang coverage. `COMPLETE` ditolak bila belum ada
halaman, bila `imported+duplicates+skipped != matched`, atau bila `matched=0` (harus `EMPTY`).
Batch key yang sama mengembalikan counts tersimpan bahkan setelah job difinalisasi; hash berbeda →
`409 idempotency_conflict`. Retry finalisasi dengan state akhir yang sama mengembalikan job yang
sudah ada (pemulihan respons hilang). Respons batch memuat `monthId`, `inputRevision`, counts dan
`jobState`.

Setiap kandidat `PARSED` harus berada di bulan `eventAt` yang sama dengan job menurut
Asia/Jakarta (batas UTC 17.00). Kandidat di luar bulan menolak **seluruh** batch sebelum record,
counter, idempotency atau revision ditulis. Fingerprint unik per owner: kandidat dari job bulan lain
dengan fingerprint sama dihitung `duplicates`, bukan baris baru.

### 7.4 Sweep internal

Deletion memerlukan password reauthentication (sekali pakai, tidak disimpan) dan konfirmasi literal
`DELETE_WORKSPACE`; body kosong/konfirmasi salah → `400`, password salah → `403`, admin aktif
terakhir → `409 last_admin`. Request yang dibuat segera mencabut seluruh sesi/refresh, sehingga
akses keuangan berikutnya `401`; status hanya dapat dibaca lewat `GET
/v1/deletion-receipts/{receiptToken}` yang mengembalikan state/timestamp tanpa data keuangan.
Write yang sudah melewati pemeriksaan awal diperiksa ulang di commit dan ditolak bila deletion
sudah menang.

Log server memakai template route tertutup (`/v1/deletion-receipts/{token}`), bukan path mentah;
token receipt tidak pernah menjadi bagian log/error/panic. `POST /v1/internal/sweep` dengan header `x-internal-token` (nilai dari `INTERNAL_SWEEP_TOKEN`).
Tanpa token konfigurasi → `404`; token salah → `401`. Sweep menghapus data finance/import/ringkasan/
analisis/attachment metadata/account key, mencabut sesi/refresh, menandai akun `DELETED`, dan
melindungi admin aktif terakhir.

---

## 8. Ringkasan

`GET /v1/summaries/{monthId}` menghitung dari transaksi aktif owner di server:
`grossInflowMinor`, `grossOutflowMinor`, `netMinor`, `classifiedIncomeMinor`,
`classifiedExpenseMinor`, `categoryTotals[{categoryId,code,label,kind,amountMinor,count}]`,
`transactionCount`, `coverage`, `inputRevision`, `emailDerived: true`, `generatedAt`.
Tidak ada upload ringkasan dari klien pada v0.4. Hasil boleh di-cache dengan kunci
`(owner,month,inputRevision,summaryVersion)`; cache tidak boleh menyajikan revisi lama.

`coverage` = `COMPLETE|PARTIAL|EMPTY|FAILED` dari import job terakhir + jumlah baris; `EMPTY` tidak
pernah berarti "tidak ada pengeluaran".

### 8.1 Analisis canonical dan freshness

Payload dari klien divalidasi sebagai envelope bertipe (unknown key, category code non-allowlist,
`transactionCount` hilang, dan nominal di luar batas ditolak), tetapi **angka yang dikirim klien
tidak dipakai**. Server membangun payload dari transaksi/kategori/anggaran aktif dan membandingkan
`inputRevision` dengan revisi bulan server; revisi basi → `409 revision_conflict` sebelum provider
dipanggil. Output provider divalidasi terhadap skema, metric key, `Rp` major→minor, angka minor
ambigu, instruksi, saran, dan jumlah observasi; maksimum satu regenerasi.

Snapshot menyimpan dependency hash yang mencakup revisi bulan target, priorMonth, state kategori,
budget plan/limits, dan import coverage. Finalisasi menghitung ulang token itu dalam transaksi
write; perubahan salah satu dependensi → `409`. Cache juga mensyaratkan token yang sama.
Withdrawal menandai report lama `HISTORICAL`.

Respons analisis (POST/GET/replay) memuat `monthId`, `inputRevision`, `currentRevision`,
`createdAt`, `status` (`AVAILABLE|HISTORICAL`) dan **`freshness`** (`CURRENT|STALE|HISTORICAL`).
`STALE` berarti laporan disimpan sebagai provenance tetapi dependensi server sudah berubah dan UI
tidak boleh menyebutnya terkini. Replay idempotency lama mengembalikan provenance dengan freshness
yang dihitung ulang, bukan otomatis `AVAILABLE/CURRENT`.

---

## 9. Anggaran, lampiran dan admin (dipensiunkan CR-008)

Modul anggaran, lampiran transaksi, dan administrasi pengguna dikeluarkan dari cakupan produk
(CR-008). Dokumen ini tidak lagi mendefinisikan kontrak HTTP untuk ketiganya; route dihapus dari
mux dan permintaan apa pun mendapat `404`. Data lama dipertahankan di tabel `budget_plans`,
`budget_limits`, `attachments`, `admin_invitations`, dan `admin_audit` tanpa perubahan skema, sehingga
penghapusan data tidak pernah menjadi efek samping dari perubahan cakupan. Analisis keuangan dan
ringkasan tidak lagi memakai anggaran sebagai dependensi yang dapat diubah pengguna; dependensi
historis yang tersimpan tetap dihitung dari baris lama bila ada.

---

## 12. Fingerprint per akun

`GET /v1/fingerprint-key` → `{ keyVersion, keyBase64 }` (hanya owner; access token valid).
Kunci 32 byte dibuat saat registrasi, disegel `AES-GCM` dengan AAD `fingerprint|owner|keyVersion`.
Klien menyimpannya di Keystore dan menghitung `HMAC-SHA256(key, "UIDVALIDITY:UID|amount|eventAt|
direction|recipient")`. Reinstall/perangkat baru mengambil kunci yang sama → fingerprint sama.
Rotasi kunci hanya dengan migrasi re-fingerprint; kunci dihapus saat akun dihapus.

---

## 13. Consent, analisis, deletion (reuse)

- `POST /v1/consents` tetap append-only; `WITHDRAWN` AI memblokir analisis berikutnya.
  Android v0.4 hanya menganggap consent sah setelah server mengakui `201`; local
  ledger tetap disimpan untuk recovery dan dapat menunjukkan pending/error.
- `POST /v1/analyses` tetap memakai allowlist `AiAggregatePayload`; backend memeriksa consent,
  owner, revisi, dan payload sebelum provider. Tidak ada transaksi/merchant di payload.
  `payload.coverage` menerima enum domain yang sama dengan summary —
  `COMPLETE|PARTIAL|EMPTY|FAILED` — plus `UNKNOWN` untuk envelope legacy v0.3; nilai lain ditolak
  `400 invalid_request` (`payload.coverage is invalid`) sebelum provider dipanggil. Bulan dengan
  coverage `EMPTY`/`FAILED` tetap boleh menghasilkan analisis opsional sesuai keputusan produk.
- `POST /v1/deletion-requests { "password": "...", "confirmation": "DELETE_WORKSPACE" }` memblokir impor/analisis selama `PENDING`; worker menghapus data
  aktif dan metadata lampiran; backup kedaluwarsa ≤30 hari.

---

## 14. Batas dan observability

| Batas | Nilai |
|---|---|
| Access TTL | ≤15 menit |
| Refresh TTL | 30 hari |
| Body | 256 KB |
| Batch impor | 100 kandidat |
| List page | 50 default / 100 max |
| Search scan | 2.000 baris, rentang ≤31 hari |
| Amount | ≤1.000.000.000.000.000 minor |
| Lampiran | 10 MB, 10/transaksi |
| Analisis | rate + daily ceiling existing (FR-50) |

Reservasi biaya provider memeriksa biaya terpakai + reservasi outstanding + biaya panggilan
berikut. `LLM_MAX_INPUT_TOKENS` dan `LLM_MAX_OUTPUT_TOKENS` menjadi batas biaya per panggilan yang
dapat ditegakkan adapter; ini **soft ceiling** terhadap tagihan provider sebenarnya, bukan hard cap
global. Ceiling yang lebih kecil dari satu panggilan menolak sebelum provider. Usage provider
dicatat dengan context background terbatas; bila pencatatan gagal, respons error dan reservasi
konservatif tetap ada.

Konfigurasi wajib produksi: `DATA_ENCRYPTION_KEY` base64 32 byte yang bukan key development;
`JWT_SECRET`/`REFRESH_PEPPER` ≥32 byte bukan nilai development; `REGISTRATION_INVITE_CODE` bukan
`pam-dev`. Boot produksi gagal sebelum database dibuka bila salah satu tidak aman.
Konfigurasi auth (environment backend, tidak pernah di APK):
`JWT_SECRET` (≥32 byte), `JWT_ISSUER=pam-api`, `JWT_AUDIENCE=pam-android`,
`ACCESS_TOKEN_TTL_SECONDS=900`, `REFRESH_TOKEN_TTL_DAYS=30`, `REFRESH_PEPPER` (≥32 byte),
`DATA_ENCRYPTION_KEY` (existing). Ganti `JWT_SECRET`/`REFRESH_PEPPER` = semua sesi lama tidak valid
dan pengguna harus login ulang; rotasi `DATA_ENCRYPTION_KEY` memerlukan re-enkripsi bertahap.

Log JSON per request: `ts, correlationId, method, path, status, ms, ownerRef, retry`; tanpa body,
email, nominal, merchant, token, ciphertext atau path file. `ownerRef` = hash pendek.

---

## 15. Pemetaan skema

| Tabel | Peran |
|---|---|
| `users` | akun, role/status, `auth_version`, `revision` |
| `auth_sessions`, `refresh_tokens` | sesi JWT + rotasi refresh |
| `account_keys` | kunci fingerprint tersegel |
| `categories`, `transactions` | CRUDS owner-scoped + field dinamis |
| `budget_plans`, `budget_limits` | **legacy CR-008**: data dipertahankan, tanpa API |
| `attachments` | **legacy CR-008**: metadata dipertahankan, tanpa API |
| `import_jobs`, `import_batches`, `import_skipped` | impor atomik/idempoten |
| `month_revisions` | revisi dependen |
| `admin_invitations`, `admin_audit` | **legacy CR-008**: data dipertahankan, tanpa API |
| `consents`, `summaries`, `analyses`, `deletion_requests`, `usage_counters` | existing |

DDL dan acceptance lokal ada di [`10_MIGRASI_PEDOMAN.md`](10_MIGRASI_PEDOMAN.md). Migrasi cloud
**NOT RUN** sampai kredensial database uji tersedia.

---

## 16. Yang harus lulus sebelum C1 dianggap selesai

1. Register/login/refresh/logout: JWT claims, TTL, revoke, rotation, replay family, role/status.
2. Dua owner: list/detail/update/delete lintas owner → 404; fingerprint sama di dua owner boleh.
3. CRUDS transaksi/kategori: `If-Match`, soft delete, reassign kategori, total berubah.
4. Impor: batch idempoten, retry tidak menduplikasi, atomic rollback, revisi naik sekali.
5. Ringkasan: angka cocok dengan calculator, `inputRevision` berubah setelah edit/hapus.
6. Modul pensiun CR-008: semua method `/v1/budget-plans*`, `/v1/attachments*`, `/v1/admin/*` → 404;
   tabel dan baris lama tetap ada; registrasi dengan `invitationToken` lama tetap berfungsi.
7. Shadow search: hanya rentang terbatas, pagination benar, ciphertext tidak di-`LIKE`.
10. Log/scan: tanpa PII; database cloud diuji terpisah dengan kredensial uji.

---

## 17. Backup, restore dan retensi (acceptance)

- Backup/export mencakup `schema_migrations`, `users`, `auth_sessions`, `refresh_tokens`,
  `account_keys`, kategori, transaksi, anggaran/limits, metadata lampiran, import job, consent,
  ringkasan/analisis dan deletion. Kunci enkripsi (`DATA_ENCRYPTION_KEY`) **tidak** disimpan di
  dump; kunci dikembalikan dari jalur terpisah.
- Restore ke database terpisah harus lolos `PRAGMA foreign_key_check` (lokal) dan pembacaan ulang
  data terenkripsi. Jumlah record dan hasil dekripsi dicatat.
- Setelah restore, **semua `auth_sessions`/`refresh_tokens` dicabut** dan pengguna login ulang.
  Ini mencegah sesi yang diterbitkan setelah titik backup tetap hidup pada keadaan lama.
- `account_keys` ikut backup; bila kunci data hilang, fingerprint tidak dapat dipulihkan dan impor
  berikutnya akan menduplikasi. Karena itu kunci data wajib disimpan terpisah dan diuji restore.
- Retensi: data aktif dihapus pada deletion request; backup kedaluwarsa ≤30 hari; file lampiran
  lokal dihapus klien dan tidak ada di backup server. PITR Free 24 jam adalah bantuan, bukan
  pengganti export harian.

## Category classification jobs (CR-004)

- `POST /v1/category-jobs` body `{"transactionIds":["…"]}`; max 5 per request.
- Requires server-confirmed `AI_CATEGORIZATION=GRANTED`; owner comes from the session.
- Considers only rows that are not USER-corrected and are uncategorized; returns durable job rows
  with `state` `PENDING|RUNNING|CLASSIFIED|NEEDS_REVIEW|FAILED|CANCELLED` plus reason/error code.
- Uses owner-scoped cache keyed by hashed merchant/direction/method/taxonomy/model/prompt; cache
  hits apply without a provider call. Unknown/unsafe/ambiguous results are NEEDS_REVIEW and never
  invent a category. Apply is revision-checked and refuses USER overrides.
- `GET /v1/category-jobs/{id}` returns one owner-scoped job.
- Output identifiers are stable `caseId`, not list indexes; model output is strict-schema validated.
- Budget gate: owner 20/day, installation 100/day, global USD0.10/day, USD2/month, 5 merchants,
  1024 input/512 completion tokens, one retry/20s target. Current implementation reserves
  worst-case cost and records attempts; it does not yet implement retry/lease recovery or actual
  token reconciliation.

---

## 18. Gmail API dan Pub/Sub (CR-006)

Kontrak rinci: [`GMAIL_API_CONTRACT.md`](GMAIL_API_CONTRACT.md); panduan Console:
[`GMAIL_API_SETUP.md`](GMAIL_API_SETUP.md). Ringkas:

- Opt-in `GMAIL_ENABLED` (default `false`); saat nonaktif `connect/start` → `503 gmail_disabled`,
  callback → `302 pam://gmail/connected?status=error&reason=gmail_disabled`, push → `503`.
  Saat nonaktif `GET /v1/gmail/status` juga menjawab `503 gmail_disabled`; Android memetakannya ke state "server belum mengaktifkan tautan Gmail", bukan gangguan jaringan.
- `POST /v1/gmail/connect/start` memerlukan sesi JWT aktif dan consent Gmail; hasil
  `authorization_url` hanya boleh dibuka owner. `state` acak 256-bit, disimpan sebagai hash,
  sekali pakai, TTL ≤10 menit, terikat owner + PKCE S256.
- `GET /v1/gmail/connect/callback?code&state` tidak memakai JWT: validasi state → tukar code →
  verifikasi email akun → simpan refresh token terenkripsi → `users.watch` → jadwalkan backfill.
  Selalu redirect ke deep link dengan `status=success|error` dan `reason` kode aman
  (`state_invalid`, `state_expired`, `gmail_disabled`, `consent_required`, …).
- Satu koneksi ACTIVE per owner; indeks unik parsial. Start saat sudah terhubung → `409`;
  `reconnect:true` mengganti akun (stop watch + revoke koneksi lama, reset job/event lama).
- `GET /v1/gmail/status` mengembalikan `connected`, `account_email_masked`, `scope`,
  `connected_at`, `last_sync_at`, `watch_expires_at`, `sync_state`, `last_error_code`.
  Token, authorization code, dan email penuh tidak pernah dikembalikan.
- `POST /v1/internal/gmail/push` diverifikasi JWT OIDC (issuer Google, audience
  `GMAIL_PUSH_AUDIENCE`, service account `GMAIL_PUSH_SERVICE_ACCOUNT`). Event idempoten
  (`event_key` unik); ACK `204` setelah event durable, duplikat tidak menambah event, mailbox tak
  dikenal di-ACK tanpa data.
- Backfill 12 bulan WIB bergulir, delta via `history.list`, cursor terenkripsi + pemulihan
  kedaluwarsa, dedupe `g:<hash email>:<messageId>` dan merge dengan identitas IMAP.

## 19. Retensi setahun (CR-005)

Rinci: [`RETENTION_POLICY_IMPLEMENTATION.md`](RETENTION_POLICY_IMPLEMENTATION.md).

- Jendela bergulir satu tahun Asia/Jakarta: mulai hari ini setahun lalu pukul 00:00 WIB, inklusif.
  Bulan batas parsial dipertahankan barisnya sampai bulan penuh kedaluwarsa. 29 Feb di-clamp ke
  28 Feb. Month ID selalu WIB.
- Request baca/tulis di luar jendela → `400 outside_retention`, envelope memuat objek `retention`
  (`windowStart`, `windowEnd`, `startMonthId`, `endMonthId`, `timezone`, `months`) dan `retryable:false`; kesalahan DB tetap `5xx`. Berlaku untuk
  transaksi list/create, ringkasan GET/PUT, analisis GET/POST, import job create/batch/read,
  lampiran create/list/by-id, dan filter bulan.
- `GET /v1/retention` mengembalikan metadata jendela untuk UI.
- Sweep: `POST /v1/internal/retention-sweep` dengan `x-internal-token` (`INTERNAL_SWEEP_TOKEN`;
  tanpa token konfigurasi → `404`, salah → `401`). Mode default `report-only` hanya menulis baris
  audit agregat. Mode `delete` memerlukan `RETENTION_DELETE_ENABLED=true` **dan**
  `?mode=delete&confirm=RETENTION_DELETE`; bila flag mati → `403 retention_delete_disabled`,
  tanpa konfirmasi → `400 confirmation_required`. Sweep terjadwal opt-in
  (`RETENTION_SWEEP_ENABLED`, interval `RETENTION_SWEEP_INTERVAL_HOURS` 1..168, default 24).
- Budget plan/FR-42 dikecualikan dari sweep dan tetap disimpan. Audit hanya memuat mode, jendela,
  timestamp, status, dan jumlah agregat — tanpa PII/owner id/token.
