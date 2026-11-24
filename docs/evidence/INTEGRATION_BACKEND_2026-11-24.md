# Bukti integrasi backend — Gmail API + retensi setahun

Tanggal: **24 November 2026** (WIB). Branch `integration/2026-11-24` (HEAD saat dokumen dibuat
`efb03e8`), gabungan `feat/gmail-api` (`7376749`) dan `feat/retention` (`a05994c`) di atas
`main` `327d876`. `main` **tidak** di-merge; merge/deploy menunggu instruksi pemilik.

## Isi pasangan

| Sumber | Perubahan |
|---|---|
| `feat/gmail-api` | migrasi 017 (tabel Gmail) + 019 (unique index job DELTA); OAuth/PKCE, klien Gmail API, parser Livin, push OIDC idempoten, worker backfill 12 bulan WIB + delta + renew, jembatan kategorisasi otomatis pasca impor |
| `feat/retention` | migrasi 018 (`retention_sweeps`); kebijakan jendela setahun WIB, guard `400 outside_retention`, `GET /v1/retention`, sweep report-only/delete dengan flag+token, worker terjadwal opt-in |
| integrasi | konflik `config.go` (union `Gmail`+`Retention`), `cmd/api/main.go` (urutan shutdown), `ImportBatch` mempertahankan kontrak Gmail (inserted ids), tes email lintas bulan disesuaikan ke pasangan bulan lampau yang diterima jendela retensi |

## Bukti otomatis (fresh, HEAD `efb03e8`)

```text
$ ./scripts/go.sh vet ./...        # bersih
$ ./scripts/go.sh test ./... -count=1
ok internal/auth        ok internal/categoryllm   ok internal/config
ok internal/crypto      ok internal/finance       ok internal/gmail 0.857s
ok internal/httpapi 25.864s                        ok internal/llm
ok internal/retention   ok internal/store
$ ./scripts/go.sh build ./...      # ok
```

Migrasi fresh DB: **19 baris** `schema_migrations` versi `1..19` (017 Gmail, 018 retensi,
019 delta). Tidak ada perubahan destruktif pada 001–016.

## Smoke server terisolasi (port 18110/18111, DB `/tmp`, bukan data owner)

| Cek | Hasil |
|---|---|
| `GET /healthz`, `GET /readyz` | 200 |
| `GET /v1/gmail/status`, `start`, `retention` tanpa JWT | 401 |
| `GET /v1/gmail/connect/callback?code=x&state=y` | 302 `pam://gmail/connected?reason=gmail_disabled&status=error` |
| `POST /v1/internal/gmail/push` saat Gmail mati | 503 |
| `POST /v1/internal/retention-sweep` tanpa token | 401 |
| … dengan token benar (`report-only`) | 200 |
| … `?mode=delete&confirm=RETENTION_DELETE` saat flag mati | 403 `retention_delete_disabled` |
| Log request | rute tertutup, tanpa query/PII/token |

## Gate NOT RUN (menunggu pemilik)

1. Google Cloud Console (project, consent screen + test users, OAuth client, Gmail API,
   Pub/Sub topic/subscription + publisher grant, endpoint HTTPS) dan E2E akun pilot.
2. Verifikasi restricted scope Gmail untuk production (CASA).
3. Sweep delete nyata pada DB produksi/UAT dan restore/rollback data nyata.
4. Merge `integration/2026-11-24` → `main` atau PR, deployment, rotasi secret.
