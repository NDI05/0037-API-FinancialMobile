# Panduan pemilik — UAT Gmail API mode polling, target GCP Rp0

Status dokumen: **kerja, 24 November 2026**. Dokumen ini untuk pemilik proyek. Tidak memuat
secret, alamat email, token, atau data transaksi. Semua kredensial hanya disimpan di profil
privat di luar repo.

## 1. Kondisi GCP yang terakhir terverifikasi (24 November 2026)

| Hal | Kondisi | Dampak |
|---|---|---|
| Project | `My First Project`, ID `project-cbea9991-e262-4947-9bd` | Dipakai untuk uji |
| Gmail API | Aktif | Prasyarat OAuth terpenuhi |
| Scope | `https://www.googleapis.com/auth/gmail.readonly` | Baca-saja, sesuai kontrak |
| OAuth audience | External / Testing | Hanya test user yang boleh consent |
| Test users | **kosong** | Login Gmail akan ditolak sampai pemilik menambahkannya |
| OAuth client | `pam-dev` (Android) | Android memakai client ini untuk login Google aplikasi |
| OAuth client Web | **belum ada** | Callback server tidak bisa dipakai untuk menukar code |
| Redirect URI | belum terdaftar | Callback `127.0.0.1:18090` belum diizinkan Google |
| Pub/Sub | tidak dibuat | Tidak diperlukan pada mode polling |
| Billing | **tertaut** | Gate GCP Rp0 belum bisa ditutup |

Keterbatasan pemeriksaan: sesi ini tidak memiliki akses konsol GCP (tidak ada `gcloud` atau sesi
browser terautentikasi). Status di atas berasal dari pemeriksaan pemilik sebelumnya. Pemilik
harus memverifikasi ulang di konsol sebelum menutup gate. Bila Billing masih tertaut, gate
**Rp0 = OPEN** dan pemilik memutuskan: lepas Billing dari project ini, atau buat project baru
tanpa Billing untuk bukti Rp0. Jangan mengaktifkan layanan berbayar, Pub/Sub, atau mengubah
Billing tanpa keputusan pemilik.

## 2. Yang harus dilakukan pemilik (urutan)

1. **Keputusan billing.** Lepaskan Billing dari project uji, atau siapkan project baru tanpa
   Billing. Catat project ID final untuk laporan gate.
2. **Test user.** Google Auth Platform → Audience → Test users → tambahkan alamat Gmail yang
   menerima notifikasi Livin. Jangan tempel alamat itu di chat, commit, atau laporan; cukup
   konfirmasi "sudah ditambahkan".
3. **OAuth client Web.** APIs & Services → Credentials → Create credentials → OAuth client ID →
   Web application, nama mis. `PAM UAT`. Tambahkan **Authorized redirect URI** persis:
   `http://127.0.0.1:18090/v1/gmail/connect/callback`
   Client `pam-dev` (Android) tetap dipakai; jangan menghapusnya.
4. **Isi profil privat** `~/.config/pam/gmail-uat.env` (permission `600`, di luar repo):
   ```
   GMAIL_CLIENT_ID=<client id Web application>
   GMAIL_CLIENT_SECRET=<client secret Web application>
   GMAIL_REDIRECT_URI=http://127.0.0.1:18090/v1/gmail/connect/callback
   ```
   Jangan menyalin secret ke chat, issue, commit, screenshot, atau log. Bila perlu, edit file
   langsung di mesin pemilik.
5. **Jalankan backend UAT lokal** (lihat bagian 3), lalu **UAT dari Android Studio** pada HP
   fisik (lihat panduan Android). Backend hanya mendengarkan di loopback; jangan membuka port
   ke internet, jangan memakai reverse proxy publik.
6. **Cek kesiapan otomatis sebelum Run** (dari root repo Android, read-only, tanpa secret):
   ```bash
   ./scripts/verify/uat_readiness.sh --backend-url http://127.0.0.1:18090 \
     --apk app/build/outputs/apk/debug/app-debug.apk
   ```
   Exit `0` = prasyarat otomatis siap; `2` = daftar prasyarat yang kurang; `1` = gagal teknis.
   Gate Gmail live (G25) dan Rp0 (G29/G37) tetap dilaporkan terpisah; SSO/onboarding mengikuti
   `pam-app/docs/GOOGLE_SSO_OWNER_SETUP.md` (gate G36).

## 3. Menjalankan backend UAT

```bash
set -a; . ~/.config/pam/gmail-uat.env; set +a
cd <workspace>/0037-Backend-Financial
PAM_GOROOT=<workspace>/pam-app/.toolchain/go ./scripts/go.sh run ./cmd/api
```

Profil privat sudah berisi `APP_ENV=development`, `GMAIL_MODE=polling`,
`GMAIL_ALLOW_LOOPBACK_REDIRECT=true`, database SQLite lokal, dan classifier/Azure nonaktif.
Callback HTTP hanya diterima untuk URL loopback persis di atas pada profil debug lokal; profil
produksi tetap wajib HTTPS. Backend harus tetap hidup selama UAT dan selama pengujian delta
otomatis (aplikasi boleh ditutup, backend tidak).

### 3a. UAT alur terkontrol dengan fake provider (bukan bukti Gmail live)

Sebelum kredensial Google asli tersedia, alur server-polling diuji pada HP fisik memakai provider
palsu (`GMAIL_PROVIDER=fake`) dengan data sintetis. Uji ini membuktikan alur aplikasi, kontrak API,
backfill bertahap, delta, dan ketahanan restart — **bukan** bukti Gmail live, bukan bukti kuota
Gmail nyata, dan bukan penutup gate Rp0. Semua akun, email, dan nominal pada fixture sintetis.

Prasyarat: profil privat terpisah `~/.config/pam/gmail-uat-fixture.env` (permission `600`, di luar
repo) berisi `APP_ENV=development`, `GMAIL_PROVIDER=fake`,
`GMAIL_ALLOW_LOOPBACK_REDIRECT=true`, `GMAIL_DEV_FIXTURE_FILE=<file JSON sintetis di luar repo>`,
judul OAuth palsu, database SQLite terpisah, dan `GMAIL_DEV_SCENARIO=normal`. Callback tetap
`http://127.0.0.1:18090/v1/gmail/connect/callback`; tidak ada kredensial Google asli di profil ini.

1. Jalankan backend fixture, lalu `adb reverse tcp:18090 tcp:18090` untuk HP debug.
2. Dari Android Studio, Run konfigurasi `app` (debug) pada HP fisik. Pastikan
   `PAM_BACKEND_BASE_URL=http://127.0.0.1:18090` dan `/readyz` dapat dijangkau dari HP.
3. Masuk dengan akun uji sintetis, beri consent Gmail di HP, lalu tautkan Gmail. Browser akan
   membuka halaman consent palsu; setujui dan aplikasi kembali lewat deep link.
4. Biarkan backfill berjalan bertahap (satu bulan per putaran). Panel status menampilkan
   "Bulan selesai: N dari 12". Untuk demo, `GMAIL_WORKER_INTERVAL_SECONDS` boleh diperkecil
   (mis. 10 detik) dan `GMAIL_DELTA_INTERVAL_SECONDS=60`; nilai itu hanya untuk fixture dan
   **bukan** default produksi (delta produksi 15 menit).
5. Tutup aplikasi, tambahkan satu pesan sintetis baru ke fixture, jalankan ulang backend. Tunggu
   delta menulis transaksi baru, lalu buka aplikasi: transaksi muncul tepat satu kali.
6. Uji "Sinkronkan sekarang", jeda tombol/`429` cooldown, dan restart backend di tengah proses.
   Catat bahwa transaksi dan cursor tidak hilang serta tidak ada duplikat.
7. Simpan bukti sebagai label **FIXTURE**: waktu impor, jumlah bulan, jumlah transaksi server vs
   Ringkasan/Transaksi, jeda delta, dan hasil restart. Jangan pernah mencampur bukti ini dengan
   klaim Gmail live atau GCP Rp0.

### 3b. UAT Gmail live akun pilot owner (24 November 2026, ronde 6)

Backfill live pertama pada profil privat owner (`127.0.0.1:18090`, OAuth nyata, polling) memindai
ratusan email Livin tetapi mengimpor **0 transaksi**. Penyebabnya bentuk produksi yang tidak
dikenal parser fixture: label di **baris sendiri** (`Penerima` lalu nama penerima di baris
berikutnya, tanpa titik dua) dan tanggal+waktu bertumpuk dengan **nama bulan Indonesia**
(`12 Okt 2026` + `pkl 09:30:45 WIB`). Perbaikan: commit `5df6be6` (label/waktu stacked) dan
`c98527b` (bulan Indonesia), diuji dengan regresi `TestParseLivinStacked*` dan
`TestParseLivinIndonesianMonthAbbreviation`; `go vet/build/test ./... -count=1` + `-race`
auth/gmail/httpapi/store **PASS**.

Setelah runtime resmi dibangun ulang dari `c98527b` dan dijalankan ulang memakai launcher owner,
impor live berjalan: ratusan transaksi Livin nyata tersimpan dengan **0 baris duplikat**
(`source_ref_hash` semua unik): **12/12 bulan backfill COMPLETE dengan 914 transaksi unik**
(mis. Nov 40/54, Okt 53/86, Sep 0 baru/79 duplikat, Agu 55/124, Apr 97/156, Des 2025 144/170). Rate limit Google ditangani backoff provider (tidak ada
kegagalan permanen). Rincian agregat — tanpa alamat email, nominal, merchant, ID pesan, atau isi
email — ada di repo Android
`pam-app/docs/evidence/GMAIL_LIVE_IMPORT_2026-11-24.md`.

**Gate G25 (Gmail live) PASS untuk akun pilot owner.** Gate **GCP Rp0 (G29/G37) tetap OPEN**
karena Billing belum dilepas dan kuota/biaya nyata belum diukur, dan **G36 (SSO Google + tombol
Run pemilik) tetap NOT RUN**.

## 4. Bukti yang diminta saat menutup gate

- Project ID dan status Billing (tidak tertaut) — screenshot konsol boleh, tanpa data pribadi.
- Konfirmasi test user ditambahkan dan Web client dibuat (nama + redirect URI, tanpa secret).
- Waktu impor, jumlah bulan tercakup, jumlah transaksi tersimpan vs Ringkasan/Transaksi.
- Waktu tunggu delta nyata (email Livin baru → transaksi tersimpan) dan bukti tidak ganda.
- Hasil restart backend dan "Sinkronkan sekarang" saat job aktif.
