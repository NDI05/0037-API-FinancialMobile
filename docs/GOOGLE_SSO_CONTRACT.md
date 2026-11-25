# Google SSO Contract

Google Sign-In untuk Android memakai **ID token** yang diverifikasi backend. Backend tidak pernah
menyimpan client secret Google SSO: client secret hanya dipakai integrasi Gmail. Semua endpoint
SSO selalu terdaftar; bila `GOOGLE_SSO_ENABLED=false` semuanya menjawab `503 google_sso_disabled`.

## Konfigurasi

| Env | Wajib | Default | Keterangan |
| --- | --- | --- | --- |
| `GOOGLE_SSO_ENABLED` | tidak | `false` | Menyalakan endpoint SSO. |
| `GOOGLE_SSO_CLIENT_ID` | ya bila enabled | – | **Web Client ID** OAuth dari Google Cloud Console (bukan Android client ID, bukan secret). |
| `GOOGLE_SSO_JWKS_URL` | tidak | `https://www.googleapis.com/oauth2/v3/certs` | Override JWKS. `http` hanya diterima untuk `APP_ENV=development` + host loopback (test), selain itu wajib HTTPS. |
| `GOOGLE_SSO_NONCE_TTL_SECONDS` | tidak | `600` | Masa berlaku nonce, 60–3600 detik. |

Setup owner: buat OAuth Client ID bertipe **Web application** di Google Cloud Console, salin
`GOOGLE_SSO_CLIENT_ID`, isi authorized origin/redirect seperlunya untuk console. Client ID yang sama
dipakai Android sebagai `serverClientId` saat meminta ID token. Tidak ada secret yang perlu
disimpan untuk SSO.

## Alur nonce

1. Android memanggil `GET /v1/auth/google/nonce`.
2. Backend menyimpan nonce acak 32 byte (base64url) dengan masa berlaku `NonceTTL`.
3. Android meminta ID token ke Google dengan `nonce` tersebut.
4. Android mengirim `POST /v1/auth/google` (login **dan** pendaftaran langsung) atau
   `/v1/auth/google/link` (menautkan akun yang sudah login) berisi `idToken` + `nonce`.
5. Backend **mengonsumsi nonce lebih dulu** dengan satu `UPDATE ... WHERE consumed_at IS NULL`,
   lalu memverifikasi token. Nonce bersifat sekali pakai: request kedua (termasuk replay token yang
   sama) gagal `401 google_invalid_token`.

## Endpoint

### `GET /v1/auth/google/nonce` (anonymous)

`200`:

```json
{"nonce":"<base64url 32B>","expiresAt":"2026-11-24T10:10:00Z","expiresInSeconds":600}
```

`503 google_sso_disabled` bila fitur mati.

### `POST /v1/auth/google` (anonymous)

Body: `{"idToken":"<JWT Google>","nonce":"<nonce>"}`.

`200` sesi identik dengan `POST /v1/sessions` (`accessToken`, `accessExpiresAt`, `expiresAt`,
`refreshToken`, `refreshExpiresAt`, `displayName`, `user`) **plus** `"googleLinked": true`.
Refresh token hasil SSO ikut rotasi normal lewat `POST /v1/sessions/refresh`.

Ini adalah jalur login dan pendaftaran langsung (keputusan pemilik 25 November 2026): identitas yang
belum tertaut tidak lagi ditolak. Bila `email_verified=true`, backend menautkan identitas Google ke
akun yang memiliki email tersebut, atau membuat akun `USER` baru bila email belum dipakai. Email
yang tidak diverifikasi Google tidak dapat membuat maupun mengklaim akun.

Error:

| Status | code | Arti |
| --- | --- | --- |
| 400 | `invalid_request` | `idToken`/`nonce` kosong atau kepanjangan. |
| 401 | `google_invalid_token` | Signature/alg/issuer/audience/expired/nonce salah, atau nonce tidak dikenal/kedaluwarsa/sudah dipakai. |
| 403 | `google_email_unverified` | Token valid tetapi Google tidak memverifikasi email identitas ini; tidak ada akun/tautan yang dibuat. |
| 403 | `account_inactive` | Identitas tertaut, tetapi akun `users.status != ACTIVE`. |
| 409 | `google_identity_conflict` | Email sudah dimiliki akun PAM yang tertaut ke identitas Google lain; tautan lama tidak pernah dipindahkan. |
| 503 | `google_sso_disabled` | Fitur mati. |

`409 google_identity_not_linked` hanya muncul untuk keadaan yatim (baris identitas tertaut tetapi akun
tujuannya sudah tidak ada); ini bukan jalur normal login/daftar lagi.

### `POST /v1/auth/google/link` (Bearer access token)

Body sama. Menautkan identitas Google ke akun pemilik token.

`200`: `{"linked":true,"googleLinked":true}`. Menautkan identitas yang sama berulang kali tetap
`200` (idempoten).

| Status | code | Arti |
| --- | --- | --- |
| 400 | `invalid_request` | Body tidak lengkap. |
| 401 | `google_invalid_token` | Token/nonce tidak valid. |
| 403 | `account_inactive` | Akun pemilik token tidak aktif. |
| 409 | `google_identity_conflict` | `(issuer, sub)` sudah tertaut ke akun PAM lain. |
| 409 | `google_already_linked` | Akun ini sudah punya identitas Google berbeda. |
| 503 | `google_sso_disabled` | Fitur mati. |

### `GET /v1/me`

Tambahan aditif: `"googleLinked": true|false`.

## Verifikasi token

- Hanya `RS256`. `alg` lain (termasuk `none`/`HS256`) ditolak.
- JWKS di-cache ±5 menit, menghormati `kid`; `kid` tak dikenal dan TTL kedaluwarsa memicu refetch
  yang dibatasi ~15 detik, termasuk setelah fetch gagal, agar outage tidak memperlambat setiap
  login. Saat JWKS sedang down, key lama tetap dipakai; cache kosong = fail closed.
- Issuer harus `accounts.google.com` atau `https://accounts.google.com`.
- Audience harus sama dengan `GOOGLE_SSO_CLIENT_ID`.
- `exp` wajib; `nbf`/`iat` dicek dengan toleransi clock kecil (~2 menit).
- Claim `nonce` harus sama dengan nonce yang baru dikonsumsi.
- `sub` wajib dan menjadi kunci identitas bersama `issuer`.
- `email` dipakai untuk mencari/membuat akun **hanya bila `email_verified=true`**. Email tanpa
  verifikasi tidak boleh membuat akun, mengklaim email yang sudah ada, atau menautkan apa pun.
- `name` dipakai sebagai display name akun baru (dipotong 80 rune); bila kosong, bagian lokal email
  yang dipakai. Bila identitas sudah tertaut, tautan dan akun lama tetap otoritatif meskipun email
  Google berubah.

## Data dan migrasi

Migrasi `021.sql` menambah:

- `google_identities(issuer, subject, owner_id, email, created_at, last_login_at)`
  PK `(issuer, subject)`, `UNIQUE(owner_id)`, FK `owner_id → users(owner_id) ON DELETE CASCADE`.
- `google_sso_nonces(nonce PK, expires_at, consumed_at)` + index `expires_at`.

Konsistensi: nonce dikonsumsi atomik (`UPDATE` + rows affected), penautan berjalan dalam
transaksi; unique violation saat balapan dipetakan ke `409`, sehingga dua request paralel hanya
menghasilkan satu pemenang.

## Catatan keamanan

- Nonce sekali pakai, terikat ke satu request; mencegah replay ID token.
- Auto-merge berdasarkan **email terverifikasi** adalah keputusan pemilik 25 November 2026: login
  Google ke email yang sudah terdaftar menautkan akun tersebut. Account takeover dicegah karena
  Google harus memverifikasi kepemilikan email, `(issuer, subject)` yang sudah tertaut tidak pernah
  dipindahkan, dan tautan berbeda untuk email yang sama menghasilkan `409 google_identity_conflict`.
- Akun yang dibuat lewat Google saja diberi digest password acak yang tidak diketahui siapa pun,
  sehingga login password untuk email tersebut tidak dapat ditebak; pemilik dapat menautkan atau
  mengatur ulang kata sandi lewat jalur akun yang ada.
- Client secret Google tidak pernah dikirim ke Android dan tidak dipakai SSO; secret Gmail tetap
  hanya di backend.
- ID token tidak boleh dicatat ke log (hanya error code). Dokumen/test memakai token sintetis
  dengan RSA key lokal, bukan token Google asli.
