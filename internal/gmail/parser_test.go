package gmail

import (
	"strings"
	"testing"
	"time"
)

const livinDebitBody = `Halo Kak,

Pembayaran Berhasil

Penerima: KOPI KENANGAN
Merchant: KOPI KENANGAN CABANG UJI
Merchant PAN: 936009110000123456
Customer PAN: 936000110000654321
No. Referensi: 202611100001234
Jumlah: Rp 25.000
Tanggal: 10 Nov 2026 09:30:45

Terima kasih telah menggunakan Livin' by Mandiri.
`

func rawEmail(subject, body string) []byte {
	return []byte("From: Livin <no-reply@livin.co.id>\r\n" +
		"To: user@gmail.test\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" + body)
}

func TestParseLivinPrefersBusinessNameAndNeverPAN(t *testing.T) {
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", livinDebitBody))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		t.Fatalf("expected PARSED, got %+v", parsed)
	}
	if parsed.MerchantLabel != "KOPI KENANGAN" {
		t.Fatalf("Penerima must win over Merchant: %q", parsed.MerchantLabel)
	}
	for _, identifier := range []string{"936009110000123456", "936000110000654321", "202611100001234"} {
		if strings.Contains(parsed.MerchantLabel, identifier) || strings.Contains(parsed.Description, identifier) {
			t.Fatalf("identifier %s leaked into a stored label", identifier)
		}
	}
	if parsed.AmountMinor != 25000 {
		t.Fatalf("amount = %d, want 25000", parsed.AmountMinor)
	}
	if parsed.Direction != "DEBIT" {
		t.Fatalf("direction = %s", parsed.Direction)
	}
	want := time.Date(2026, 11, 10, 9, 30, 45, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

func TestParseLivinRejectsIdentifierOnlyMerchant(t *testing.T) {
	body := `Pembayaran Berhasil
Penerima: 936009110000123456
No. Referensi: 202611100001234
Jumlah: Rp 10.000
Tanggal: 10 Nov 2026 09:30
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	// A numeric Penerima is treated as an identifier, so the row stays unresolved instead of
	// importing the merchant PAN as a merchant name.
	if parsed.Status != "UNRESOLVED" || parsed.MerchantLabel != "" {
		t.Fatalf("a PAN-only Penerima must stay unresolved: %+v", parsed)
	}
	missing := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!",
		Text: "Jumlah: Rp 10.000\nTanggal: 10 Nov 2026 09:30\n"})
	if missing.Status != "UNRESOLVED" || missing.Reason != "merchant_missing" {
		t.Fatalf("missing merchant must stay unresolved: %+v", missing)
	}
}

func TestParseLivinCreditAndTemplateGuard(t *testing.T) {
	credit := ParseLivinNotification(DecodedMessage{Subject: "Transaksi Berhasil",
		Text: "Transfer Masuk\nPenerima: BUDI\nJumlah: Rp 50.000\nTanggal: 10 Nov 2026 09:30\n"})
	if credit.Status != "PARSED" || credit.Direction != "CREDIT" {
		t.Fatalf("incoming transfer must be CREDIT: %+v", credit)
	}
	unknown := ParseLivinNotification(DecodedMessage{Subject: "Newsletter",
		Text: "Penerima: TOKO\nJumlah: Rp 1.000\nTanggal: 10 Nov 2026 09:30\n"})
	if unknown.Status != "UNRESOLVED" || unknown.Reason != "template_unknown" {
		t.Fatalf("non-Livin email must not be imported: %+v", unknown)
	}
}

func TestParseIDRAmountVariants(t *testing.T) {
	cases := map[string]int64{
		"25.000":    25000,
		"25.000,00": 25000,
		"25,000.00": 25000,
		"25000":     25000,
		"1.250.000": 1250000,
	}
	for raw, want := range cases {
		got, ok := parseIDRAmount(raw)
		if !ok || got != want {
			t.Fatalf("parseIDRAmount(%q) = %d,%v want %d", raw, got, ok, want)
		}
	}
	if _, ok := parseIDRAmount(""); ok {
		t.Fatal("empty amount must be rejected")
	}
}

func TestDecodeMessageMultipartBase64(t *testing.T) {
	raw := []byte("From: Livin <no-reply@livin.co.id>\r\n" +
		"Subject: =?UTF-8?B?UGVtYmF5YXJhbiBCZXJoYXNpbCE=?=\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=batas\r\n" +
		"\r\n--batas\r\nContent-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		"UGVtYmF5YXJhbiBCZXJoYXNpbApQZW5lcmltYTogS09QSSBLRU5BTkdBTgpKdW1sYWg6IFJwIDI1LjAwMApUYW5nZ2FsOiAxMCBOb3YgMjAyNiAwOTozMAo=" +
		"\r\n--batas--\r\n")
	decoded, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" || parsed.MerchantLabel != "KOPI KENANGAN" || parsed.AmountMinor != 25000 {
		t.Fatalf("multipart/base64 body not decoded: %+v", parsed)
	}
}
