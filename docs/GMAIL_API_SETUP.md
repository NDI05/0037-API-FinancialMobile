# Gmail API setup (OAuth + Pub/Sub push)

Panduan ini menyiapkan integrasi Gmail API untuk backend PAM: consent OAuth **read-only**,
notifikasi push lewat Google Cloud Pub/Sub, dan backfill riwayat Livin satu tahun bergulir.
Kontrak klien ada di [`GMAIL_API_CONTRACT.md`](GMAIL_API_CONTRACT.md).

Status verifikasi: langkah Google Cloud Console di dokumen ini **NOT RUN** — belum dieksekusi
terhadap project Google sungguhan. Semua perilaku backend (state OAuth sekali pakai, PKCE,
enkripsi refresh token, idempotensi push, backfill, delta, retry) diuji dengan provider palsu
di `internal/gmail/fake.go`; live run menunggu kredensial owner.

## 1. Prasyarat

- Project Google Cloud (pisahkan `pam-uat` dan `pam-production`).
- Gmail API diaktifkan.
- OAuth consent screen jenis **External**, status **Testing** selama pilot (maksimal 100 test
  user), lalu **In production** setelah scope diverifikasi.
- Domain/situs kebijakan privasi dan halaman consent PAM yang menjelaskan akses Gmail.

## 2. Langkah Google Cloud Console (NOT RUN)

1. **Project**: buat project `pam-uat` (dan `pam-production` terpisah); jangan pakai project
   pribadi.
2. **Gmail API**: `APIs & Services → Library → Gmail API → Enable`.
3. **OAuth consent screen**:
   - User type: External. Isi nama app `PAM`, email dukungan, logo, dan link privacy policy.
   - Scopes: hanya `https://www.googleapis.com/auth/gmail.readonly`
     (`openid`, `email`, `profile` boleh ditambahkan untuk identitas).
   - Testing: tambahkan test users (akun Gmail pilot). Untuk production, ajukan verifikasi
     scope restricted/ sensitive (Gmail readonly tergolong restricted); siapkan video demo,
     penjelasan penggunaan data, dan justifikasi scope.
4. **OAuth client**: `Credentials → Create credentials → OAuth client ID → Web application`.
   - Authorized redirect URI: `https://<host-api>/v1/gmail/connect/callback`
     (harus persis sama dengan `GMAIL_REDIRECT_URI`; HTTP biasa ditolak backend).
   - Simpan client ID + client secret ke secret manager, **bukan** repo.
5. **Pub/Sub**:
   - Buat topic `projects/<project>/topics/gmail-push`.
   - Buat subscription tipe **Push** ke `https://<host-api>/v1/internal/gmail/push`
     dengan OIDC service account.
   - Buat service account `pubsub-push@<project>.iam.gserviceaccount.com`, beri role
     `roles/pubsub.publisher` pada topic (agar Gmail boleh publish) dan `roles/pubsub.subscriber`
     pada subscription (untuk delivery push).
   - Saat membuat subscription push, aktifkan **Enable authentication** dan pilih service
     account tadi; audience = URL endpoint push.
   - Set `GMAIL_PUBSUB_TOPIC`, `GMAIL_PUSH_AUDIENCE`, `GMAIL_PUSH_SERVICE_ACCOUNT` sesuai nilai
     ini.
6. **Endpoint HTTPS**: backend harus punya TLS valid (load balancer/Cloud Run). Pub/Sub hanya
   mengirim push ke HTTPS; verifikasi JWT OIDC gagal bila audience/issuer tidak cocok.
7. **Uji**: hubungkan satu akun pilot lewat app (`POST /v1/gmail/connect/start`), pastikan
   callback mendarat di `pam://gmail/connected?status=success`, status `connected: true`, dan
   email test Livin memicu baris push di log (tanpa alamat email/ID di log).

## 3. Environment backend

Gmail nonaktif secara default; tanpa kredensial semua fitur lain tetap jalan dan rute Gmail
menjawab `503 gmail_disabled`.

| Env | Wajib saat `GMAIL_ENABLED=true` | Default | Catatan |
| --- | --- | --- | --- |
| `GMAIL_ENABLED` | — | `false` | Aktifkan integrasi. |
| `GMAIL_CLIENT_ID` | ya | — | OAuth client ID. |
| `GMAIL_CLIENT_SECRET` | ya | — | OAuth client secret (secret manager). |
| `GMAIL_REDIRECT_URI` | ya | — | HTTPS `.../v1/gmail/connect/callback`, tanpa query/fragment. |
| `GMAIL_PUBSUB_TOPIC` | ya | — | `projects/<p>/topics/gmail-push`. |
| `GMAIL_PUSH_AUDIENCE` | ya | — | Audience JWT push = URL endpoint. |
| `GMAIL_PUSH_SERVICE_ACCOUNT` | ya | — | Email service account Pub/Sub. |
| `GMAIL_APP_DEEP_LINK` | tidak | `pam://gmail/connected` | Deep link app. |
| `GMAIL_AUTH_URL` | tidak | Google OAuth | Override untuk pengujian. |
| `GMAIL_TOKEN_URL` | tidak | Google token | Override untuk pengujian. |
| `GMAIL_REVOKE_URL` | tidak | Google revoke | Override untuk pengujian. |
| `GMAIL_JWKS_URL` | tidak | `https://www.googleapis.com/oauth2/v3/certs` | JWKS verifikasi push. |
| `GMAIL_SCOPE` | tidak | `https://www.googleapis.com/auth/gmail.readonly` | Jangan perluas. |
| `GMAIL_STATE_TTL_SECONDS` | tidak | `600` | Maksimum 600 (10 menit). |
| `GMAIL_BACKFILL_MONTHS` | tidak | `12` | Jendela bergulir, maksimum 12. |
| `GMAIL_WATCH_RENEW_BEFORE_HOURS` | tidak | `24` | Renew `users.watch` sebelum kedaluwarsa. |
| `GMAIL_WORKER_INTERVAL_SECONDS` | tidak | `60` | Tick coordinator. |
| `GMAIL_PAGE_SIZE` | tidak | `50` | `messages.list` per halaman. |
| `GMAIL_MAX_PAGES_PER_RUN` | tidak | `5` | Batas kerja per tick (manual & timer). |

Validasi production menolak konfigurasi Gmail yang tidak lengkap dan redirect URI non-HTTPS.

## 4. Alur runtime

1. **Start** (`POST /v1/gmail/connect/start`) membuat `state` sekali pakai + PKCE S256, terikat
   owner, TTL ≤10 menit. `reconnect: true` mengganti koneksi lama (watch lama di-stop dulu).
2. **Callback** (`GET /v1/gmail/connect/callback`) memvalidasi state, menukar `code`,
   memverifikasi email akun, menyimpan refresh token terenkripsi (AES-256-GCM via
   `internal/crypto`), menjalankan `users.watch`, lalu redirect ke deep link
   `pam://gmail/connected?status=success|error&reason=<safe_code>`. State dipakai sekali;
   replay/kedaluwarsa dijawab `state_invalid`/`state_expired`.
3. **Push** (`POST /v1/internal/gmail/push`, bukan sesi PAM) diverifikasi JWT OIDC (issuer
   Google, audience env, service account env). Owner **hanya** ditentukan dari hash email
   tersimpan; email tak dikenal di-ACK tanpa menyimpan data. Event disimpan idempoten
   (`event_key` unik) lalu diproses worker.
4. **Worker**: memperbarui watch yang mau kedaluwarsa, lalu memproses delta (cursor
   `history.list`) atau backfill bulan bergulir paling baru yang belum selesai — maksimum
   `GMAIL_MAX_PAGES_PER_RUN` halaman per tick. Checkpoint halaman disimpan setelah batch impor
   diakui; percobaan ulang tidak menggandakan transaksi (dedupe per owner + source ref).
5. **Delta kedaluwarsa** (404/`history.list` invalid): scan ulang bulan berjalan (aman karena
   dedupe), ambil cursor baru dari `users.getProfile`, lanjut.
6. **Kategorisasi otomatis ikut jalan**: setelah satu batch impor diakui, worker hanya
   meng-enqueue transaksi yang benar-benar baru (dengan consent `AI_CATEGORIZATION` GRANTED)
   tanpa memanggil provider, lalu menjalankan satu jendela drain server-side yang dibatasi
   (konstanta `CategoryDrainBatch` = 5 merchant/request, `CategoryDrainMaxBatches` = 4 request
   per jendela 2 jam, single-flight per owner). Budget/attempt/token gate tetap berlaku dan
   penolakan budget tidak menghapus transaksi. Idempoten: replay batch tidak menambah job.
7. **Disconnect** (`POST /v1/gmail/disconnect`): stop watch, revoke token bila mungkin, hapus
   kredensial tersimpan, tolak pekerjaan baru. Transaksi yang sudah dikonfirmasi tidak dihapus.

## 5. Keamanan dan batas data

- Scope hanya `gmail.readonly`; tidak ada tulis/hapus email.
- Refresh token, email akun, payload push, dan page token disimpan terenkripsi (AAD terikat
  owner + purpose + key version).
- Raw MIME hanya ada di memori selama parsing; Penerima/Merchant dipakai sebagai label,
  sedangkan **Merchant PAN, Customer PAN, No. Referensi tidak** pernah disimpan atau di-log.
- Tidak ada alamat email penuh, ID Gmail mentah, token, atau isi email di log. `sanitizedRoute`
  memetakan callback/push ke label tetap.
- Dedupe key: `source_ref = g:<16 hex hash email>:<gmail message id>` (hash per owner-mailbox),
  konsisten setelah reconnect.

## 6. Uji lokal tanpa Google

```bash
export PAM_GOROOT=/path/to/go1.27.4
./scripts/go.sh test ./internal/gmail ./internal/httpapi ./internal/store -count=1
```

Tes memakai `FakeProvider`, `FakeExchanger`, dan `FakePushVerifier` — tanpa jaringan, tanpa
kredensial. Yang dicakup: state replay/expired, PKCE, isolasi owner, token terenkripsi,
push JWT salah/benar, idempotensi event, dedupe, filter periode, cursor kedaluwarsa, retry,
renewal watch, serta jembatan kategorisasi (enqueue hanya baris baru + consent, drain
terbatas/single-flight, budget tidak menghapus transaksi).

## 7. Gate yang belum dijalankan (menunggu owner)

- Pembuatan project/consent screen/OAuth client/pub-sub nyata.
- Verifikasi scope restricted Google (production).
- Live end-to-end dengan akun pilot: connect → backfill setahun → email Livin baru → delta.
- Rotasi/penghapusan client secret dan service account sesuai kebijakan secret.
