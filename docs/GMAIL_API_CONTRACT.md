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

- Auth wajib. Memanggil `users.stop` watch, mencabut token bila mungkin, menghapus kredensial
  tersimpan, menolak pekerjaan baru. Respons `200 {"disconnected": true}`.
- Data transaksi yang sudah dikonfirmasi **tidak** dihapus oleh disconnect (retensi terpisah).

## 5. Pub/Sub push (internal, tidak dipakai Android)

`POST /v1/internal/gmail/push` — diverifikasi dengan OIDC JWT (issuer Google, audience env,
service account env), resolve owner **hanya** lewat koneksi server (email di payload), simpan
event durable lalu ACK 2xx. Event ganda/terlambat harus idempoten.

## 6. Catatan Android

- App hanya perlu: tombol "Tautkan Gmail" (panggil start, buka URL), deep link
  `pam://gmail/connected`, tampilan status, dan tombol "Putuskan".
- Polling status saat resume; jangan simpan token/email penuh di perangkat.
- Consent PAM terpisah: Gmail, kategorisasi AI, Analisis AI.
