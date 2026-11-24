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

## 4. Bukti yang diminta saat menutup gate

- Project ID dan status Billing (tidak tertaut) — screenshot konsol boleh, tanpa data pribadi.
- Konfirmasi test user ditambahkan dan Web client dibuat (nama + redirect URI, tanpa secret).
- Waktu impor, jumlah bulan tercakup, jumlah transaksi tersimpan vs Ringkasan/Transaksi.
- Waktu tunggu delta nyata (email Livin baru → transaksi tersimpan) dan bukti tidak ganda.
- Hasil restart backend dan "Sinkronkan sekarang" saat job aktif.
