# Perbaikan satuan nominal impor Gmail — 25 November 2026

**Commit:** `d42d7c4` (`fix(gmail): parse Livin amounts as minor units and repair imported rows`)
**Repo:** `0037-Backend-Financial` · **Build diverifikasi:** `/tmp/pam-api-d42d7c4`
sha256 `4c88bc46d323825784f768a5fc99a2b3a5c0f4e5f2c4a09141bafae5758bc48f`
**Basis:** `docs/API_CONTRACT.md:23` — nominal selalu integer **minor IDR (1/100 rupiah)**.

## Gejala yang dilaporkan pemilik

Transaksi hasil impor email Livin tampil **100x lebih kecil** dari nominal di email: angka nol
kurang (contoh: nominal email Rp25.000 tampil Rp250). Entri manual tidak terpengaruh.

## Akar masalah

1. `internal/gmail/livin.go` — `parseIDRAmount` mengembalikan **rupiah utuh** (`"25.000"` → `25000`)
   dengan komentar lama "IDR has no circulating cents".
2. Seluruh jalur lain memakai **minor unit**: entri manual Android mengirim sen, Android
   `Money` membagi 100 saat menampilkan, dan kontrak API menyebut minor unit. Jadi baris
   `source=EMAIL` tersimpan 100x terlalu kecil.
3. Bug tertutup oleh fixture: `internal/gmail/devfake.go` mencetak
   `"Jumlah: Rp " + devThousands(message.AmountMinor)` lalu `devThousands` mengelompokkan nilai
   minor **seolah-olah rupiah**. Fixture dan parser sama-sama salah dengan arah yang sama, sehingga
   seluruh tes lama lulus.

## Perubahan

| Berkas | Perubahan |
|---|---|
| `internal/gmail/livin.go` | `parseIDRAmount` mengembalikan minor unit; sen yang tercetak dipertahankan eksak (`"25.000,50"` → `2_500_050`); `TemplateVersion` → `gmail-livin-v3` |
| `internal/gmail/devfake.go` | `devMinorText` mencetak rupiah mayor + sen, jadi fixture memaksa parser mengembalikan nilai minor yang dideklarasikan |
| `internal/gmail/parser_test.go` | Ekspektasi diperbarui ke minor; tabel kasus produksi (`25.000`, `1.250.000`, `100.000`, `1.000.000,00`, `25.000,50`, `9.990`) + tes round-trip fixture |
| `internal/gmail/sync_test.go` | Fixture merge lintas sumber memakai minor |
| `internal/store/migrations/022.sql` | Perbaikan sekali jalan: `amount_minor × 100` hanya untuk `source='EMAIL'` dengan `parser_version IN ('gmail-livin-v1','gmail-livin-v2')`; bump `month_revisions` agar cache ringkasan tidak menyajikan total lama |
| `internal/store/migration_amount_repair_test.go` | Membuktikan v1/v2 diskalakan tepat sekali, MANUAL dan v3 tidak tersentuh, revisi bulan ikut naik |
| `internal/store/google_sso_test.go` | Jumlah migrasi 22 |

## Verifikasi yang dijalankan (25 Nov 2026, WIB)

- `./scripts/go.sh vet ./...` → exit 0.
- `./scripts/go.sh test ./... -count=1` → **PASS 11 paket** (analysis, auth, categoryllm, config,
  crypto, finance, gmail, httpapi, llm, retention, store).
- `TestParseIDRAmountVariants` + `TestDevFixtureRoundTripsMinorAmounts` → PASS.
- `TestUpgradeRepairsLegacyEmailAmounts` + `TestSchemaHasExactly22Migrations` → PASS.
- **E2E terisolasi** (DB `/tmp`, port 18093, fake Gmail, bukan data pemilik): fixture minor
  `2_500_000` / `999_000` / `12_345_678` (Rp25.000 / Rp9.990 / Rp123.456,78) diimpor lewat
  connect → authorize → callback, lalu `GET /v1/transactions?month=2026-11` mengembalikan
  **nilai minor yang sama persis** → `AMOUNT_E2E PASS`.
- **Penerapan ke DB UAT lokal pemilik** (`~/.config/pam/pam-gmail-uat.db`, setelah backup dan
  verifikasi pada salinan lebih dulu):
  - 915 baris `source=EMAIL` (semua `gmail-livin-v1/v2`) diskalakan sekali; rentang sebelum
    `1…8.199.000` → sesudah `100…819.900.000` minor.
  - 10 baris `source=MANUAL` tidak berubah (rentang `12.345…5.000.000`).
  - `schema_migrations` = 22; `month_revisions` = 13.
  - Backend UAT `127.0.0.1:18090` (`pam-api-loopback` baru) `/healthz` dan `/readyz` = 200.

## Batas bukti

- Tidak ada email asli yang dibaca/dikutip; angka di atas hanya agregat DB UAT lokal.
- Perbaikan diterapkan ke **runtime UAT lokal**, bukan deployment produksi; deployment tetap
  menunggu instruksi terpisah.
- Analisis yang sudah tersimpan sebelum perbaikan (`analyses` berisi snapshot nominal lama) perlu
  dibuat ulang agar menampilkan total baru; ringkasan dihitung ulang dari transaksi.
- Android tidak memerlukan perubahan kode: APK yang sama membaca `amountMinor` minor dan sudah
  membagi 100 saat menampilkan; data dari server kini benar.
- Re-impor email yang sama tidak menggandakan baris karena `UNIQUE(owner_id, source_ref_hash)`;
  fingerprint lama tidak dipakai sebagai kunci dedupe lintas waktu.
- Bukti live "email Livin baru masuk saat app tertutup" (G36) tetap tugas pemilik.
