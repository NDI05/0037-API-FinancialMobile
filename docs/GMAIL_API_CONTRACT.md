# Kontrak Gmail API — klien Android ↔ backend Go (draf PM, 24 Nov 2026)

Status: **kontrak kerja**. Pemilik kontrak: repo `0037-Backend-Financial`. Perubahan kontrak
harus disepakati PM dan dicatat di sini beserta versinya.

Semua endpoint di bawah `/v1`, memakai autentikasi Bearer access token PAM kecuali endpoint
callback dan Pub/Sub push. Respons error memakai envelope standar backend.

## 1. Mulai tautkan Gmail

`POST /v1/gmail/connect/start`

- Auth: wajib (`Authorization: Bearer <access_token>`).
- Body: `{}` (opsional `{"reconnect": true}` untuk mengganti koneksi).
- Respons `200`:
  ```json
  {"authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
   "expires_at": "2026-11-24T07:00:00Z"}
  ```
- Server membuat `state` sekali pakai + PKCE, terikat ke owner dan waktu kedaluwarsa
  (≤10 menit). Android membuka `authorization_url` di browser/Custom Tab. Jangan meminta
  password Google di aplikasi.

## 2. Callback OAuth

`GET /v1/gmail/connect/callback?code=...&state=...` (tanpa Bearer; state mengikat owner)

- Sukses: `302 Location: pam://gmail/connected?status=success`
- Gagal/batal: `302 Location: pam://gmail/connected?status=error&reason=<safe_code>`
  dengan `safe_code` mis. `state_invalid`, `state_expired`, `access_denied`, `exchange_failed`,
  `scope_missing`.
- Server menukar `code`, memverifikasi email akun Gmail, menyimpan refresh token
  **terenkripsi** (format crypto yang ada), menandai satu koneksi aktif per owner, dan
  menjadwalkan backfill setahun.

## 3. Status koneksi

`GET /v1/gmail/status`

```json
{"connected": true,
 "account_email_masked": "a***@gmail.com",
 "scope": "https://www.googleapis.com/auth/gmail.readonly",
 "connected_at": "2026-11-24T07:00:00Z",
 "last_sync_at": "2026-11-24T07:15:00Z",
 "watch_expires_at": "2026-11-30T07:00:00Z",
 "sync_state": "idle",
 "last_error_code": null}
```

`sync_state`: `idle` | `backfill` | `delta` | `error` (jangan bocorkan detail internal).
Jika belum pernah terhubung: `{"connected": false, ...}` dengan field waktu `null`.

## 4. Putuskan Gmail

`POST /v1/gmail/disconnect`

- Auth wajib. Di mode push memanggil `users.stop` watch; di mode polling tidak ada watch yang
  dihentikan. Mencabut token bila mungkin, menghapus kredensial tersimpan, menolak pekerjaan
  baru. Respons `200 {"disconnected": true}`.
- Data transaksi yang sudah dikonfirmasi **tidak** dihapus oleh disconnect (retensi terpisah).

## 5. Pub/Sub push (internal, tidak dipakai Android)

`POST /v1/internal/gmail/push` — diverifikasi dengan OIDC JWT (issuer Google, audience env,
service account env), resolve owner **hanya** lewat koneksi server (email di payload), simpan
event durable lalu ACK 2xx. Event ganda/terlambat harus idempoten.

## 6. Dampak ke kategorisasi otomatis (tanpa field API baru)

- Setelah batch impor server-side diakui, transaksi baru yang eligible masuk antrean
  kategorisasi otomatis **tanpa memanggil provider**. Syarat tetap: consent
  `AI_CATEGORIZATION` `GRANTED`, budget/attempt/token gate durable, dan keputusan kategori
  manual pengguna menang.
- Saat backfill awal belum selesai, kandidat tersimpan sebagai satu antrean per pemilik.
  HTTP, pemroses otomatis, dan pemulihan lease menunggu semua bulan awal yang masih masuk
  retensi selesai. Drain API mengembalikan `not_due` selama menunggu. Setelah itu, satu
  antrean awal berjalan dalam batch yang dibatasi, dan pergantian bulan tidak mengulang
  fase awal.
- Server menjalankan jendela drain terbatas: maks. 5 merchant per request provider dan
  **maks. 4 panggilan provider nyata per jendela 2 jam** (`CategoryDrainMaxProviderCalls`).
  `SplitCandidates` dapat memecah satu batch menjadi beberapa panggilan, sehingga batas dihitung
  per panggilan provider, bukan per batch; sisa kandidat dikembalikan ke antrean PENDING untuk
  jendela berikutnya (tidak hilang, tidak dihitung sebagai retry provider). Single-flight per
  owner (tidak ada dua drain paralel). Antrean kosong = nol panggilan provider.
- Hasil klasifikasi yang terlambat tidak pernah menulis ke owner lain; kegagalan provider tidak
  menghapus transaksi. Status/field API tidak berubah — klien tetap memakai kontrak di atas.

## 7. Perilaku sinkronisasi yang mengikat klien

Tanpa menambah field API, perilaku berikut disepakati:

- Bulan transaksi mengikuti **tanggal transaksi** hasil parser notifikasi, bukan tanggal email
  diterima. Email yang datang terlambat (lintas bulan) tetap masuk ke bulan transaksinya;
  transaksi di luar jendela retensi 12 bulan ditolak dengan alasan eksplisit, tidak dibuang diam-diam.
- `reconnect: true` dengan mailbox berbeda me-revoke token lama dan mereset progres sinkron
  mailbox lama; mailbox baru memulai backfill 12 bulan dari awal. Replay state OAuth lama tidak
  mengaktifkan koneksi lama.
- `sync_state` tetap memakai nilai yang telah ada (`idle`, `backfill`, `delta`, `error`);
  `needs_reauth` dilaporkan lewat `last_error_code`, dan pada kondisi itu Android harus meminta
  pengguna reconnect. Gangguan provider sementara di-retry dengan backoff server-side.
- Setelah Gmail API aktif, impor IMAP/app-password untuk mailbox yang sama tidak boleh
  dijalankan (Gmail API satu-satunya jalur server). Notifikasi Gmail yang transaksinya sudah
  pernah diimpor lewat IMAP dikenali sebagai duplikat lintas sumber.

## 8. Catatan Android

- App hanya perlu: tombol "Tautkan Gmail" (panggil start, buka URL), deep link
  `pam://gmail/connected`, tampilan status, dan tombol "Putuskan".
- Polling status saat resume; jangan simpan token/email penuh di perangkat.
- Consent PAM terpisah: Gmail, kategorisasi AI, Analisis AI.

## 9. Revisi kontrak v2 — mode polling Rp0 + sinkron manual (24 Nov 2026)

Status: **kontrak kerja v2**, pemilik repo backend. Perubahan aditif/backward compatible untuk
klien lama; Android wajib memakai field/endpoint baru untuk UAT HP fisik.

### 9.1 Mode transport

- `GMAIL_MODE=polling` (default produksi UAT): OAuth, backfill, dan delta berjalan **tanpa**
  Pub/Sub. Server tidak memanggil `users.watch`/`users.stop`, tidak menginisialisasi verifier
  push, dan tidak mengekspos perilaku push. Endpoint `POST /v1/internal/gmail/push` dijawab
  `404 not_found` pada mode ini.
- `GMAIL_MODE=push` (opt-in rollback): perilaku Pub/Sub lama dipertahankan. Konfigurasi
  `GMAIL_PUBSUB_TOPIC`, `GMAIL_PUSH_AUDIENCE`, `GMAIL_PUSH_SERVICE_ACCOUNT` wajib hanya pada
  mode ini; pada mode polling nilainya boleh kosong dan diabaikan.
- Koneksi lama yang masih memiliki watch dari mode push: pada mode polling watch tidak
  diperpanjang dan dianggap kedaluwarsa; cursor/riwayat transaksi dipertahankan, tidak ada
  reset. Transisi push → polling didokumentasikan di `GMAIL_API_SETUP.md`.

### 9.2 Endpoint status (diperluas)

`GET /v1/gmail/status` — field lama tetap; tambahan (null bila belum ada):

```json
{
  "connected": true,
  "account_email_masked": "a***@gmail.com",
  "scope": "https://www.googleapis.com/auth/gmail.readonly",
  "connected_at": "2026-11-24T07:00:00Z",
  "last_sync_at": "2026-11-24T07:15:00Z",
  "watch_expires_at": null,
  "sync_state": "backfill",
  "last_error_code": null,
  "needs_reauth": false,
  "last_attempt_at": "2026-11-24T07:15:00Z",
  "last_success_at": "2026-11-24T07:10:00Z",
  "next_sync_at": "2026-11-24T07:30:00Z",
  "sync_requested_at": null,
  "progress": {
    "phase": "backfill",
    "month": "2026-11",
    "months_done": 2,
    "months_total": 13,
    "pages_done": 3
  }
}
```

- `needs_reauth=true` berarti grant dicabut/token tidak dapat diperbarui; Android menampilkan
  CTA **Tautkan ulang Gmail** ke layar kontrak §1–§2.
- `sync_state` tetap `idle|backfill|delta|error`; `progress` boleh `null` saat idle.
- `months_total` adalah jumlah bulan WIB dalam window NFR-15: 12 bulan rolling, ditambah bulan
  parsial tertua bila window mulai di tengah bulan (FR-16 "including any partial first month"),
  sehingga nilainya 12 atau 13. `months_done` menghitung bulan yang job backfill-nya sudah COMPLETE.
- Semua waktu UTC RFC3339; UI memformat WIB. Endpoint tidak pernah mengembalikan email penuh,
  token, ID pesan, atau isi email.

### 9.3 Sinkronkan sekarang

`POST /v1/gmail/sync` — auth Bearer wajib.

- `202 {"queued": true, "coalesced": false, "requested_at": "...", "next_allowed_at": "..."}`
  Permintaan masuk antrean durable yang sama dengan worker; selamat setelah restart.
- Jika job/permintaan aktif untuk owner yang sama: `202 {"queued": true, "coalesced": true, ...}`
  (tidak membuat job kedua).
- Dalam cooldown (default 60 s): `429 {"code": "sync_cooldown", "retryable": true,
  "retryAfterSeconds": 24}`.
- Gmail belum aktif: `503 gmail_disabled`; belum terhubung: `409 gmail_not_connected`; grant
  dicabut: `409 gmail_needs_reauth` (jangan mengantrekan job yang tidak akan pernah diproses).
- `sync_requested_at` pada status hanya terisi selama job yang dipicu permintaan manual belum
  selesai; server membersihkannya saat job DELTA selesai, termasuk bila hasilnya kosong.
- Endpoint hanya mengantrekan; tidak menunggu job selesai dan tidak pernah memulai impor saat
  sheet dibuka.

### 9.4 Perilaku worker

- Delta otomatis minimal setiap **15 menit** per owner (`GMAIL_DELTA_INTERVAL_SECONDS=900`);
  timer tidak menumpuk job dan tidak memanggil Gmail saat belum due.
- Backfill 12 bulan berjalan bertahap (maksimum halaman per tick) dan **memberi giliran** kepada
  delta: delta due diproses lebih dulu, lalu satu unit backfill.
- Satu owner maksimal satu job DELTA terbuka (unique index 019). Permintaan manual bergabung
  dengan job aktif, dedupe per owner+jenis, dan cooldown dihitung dari permintaan terakhir.
- Mode polling kosong: nol unduhan isi email dan nol panggilan kategori/Azure.
