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

// Production Livin notification emails put the "Penerima" label alone on its line with the
// business name on the next line (no colon). Fixtures used the inline form, so this stacked
// layout regressed to merchant_missing during live UAT; both layouts must keep parsing.
func TestParseLivinStackedLabelLayout(t *testing.T) {
	body := `Halo Kak,

Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal: 24 Nov 2026 09:30:45

Terima kasih telah menggunakan Livin' by Mandiri.
`
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		t.Fatalf("stacked label layout must parse, got %+v", parsed)
	}
	if parsed.MerchantLabel != "WARUNG SEDERHANA" {
		t.Fatalf("merchant = %q, want WARUNG SEDERHANA", parsed.MerchantLabel)
	}
	if parsed.AmountMinor != 25000 {
		t.Fatalf("amount = %d, want 25000", parsed.AmountMinor)
	}
	want := time.Date(2026, 11, 24, 9, 30, 45, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

// A bare downstream line that is itself a label or an identifier must not be accepted as the
// business name.
func TestParseLivinStackedLabelRejectsIdentifiers(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
936009110000123456

Nominal Transaksi Rp 10.000,00
Tanggal: 24 Nov 2026 09:30:45
`
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status == "PARSED" {
		t.Fatalf("identifier must not become a merchant label: %+v", parsed)
	}
}

// Production emails stack the time on the line after the date with a "pkl" marker.
func TestParseLivinStackedDateTimeLayout(t *testing.T) {
	body := `Halo Kak,

Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
pkl 09:30:45 WIB

Terima kasih telah menggunakan Livin' by Mandiri.
`
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		t.Fatalf("stacked date/time layout must parse, got %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 9, 30, 45, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

// Older production templates print the date with Indonesian month abbreviations.
func TestParseLivinIndonesianMonthAbbreviation(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 12 Okt 2026
pkl 09:30:45 WIB
`
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		t.Fatalf("Indonesian month must parse, got %+v", parsed)
	}
	want := time.Date(2026, 10, 12, 9, 30, 45, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

// A bare "Penerima" label stacked directly above another field line must not turn that field into
// the merchant name (the next line is an amount, a date, or a reference).
func TestParseLivinStackedLabelRejectsFieldLines(t *testing.T) {
	for _, nextLine := range []string{
		"Nominal Transaksi Rp 25.000,00",
		"Tanggal: 24 Nov 2026 09:30:45",
		"No. Referensi ABC123XYZ",
		"pkl 09:30:45 WIB",
	} {
		t.Run(nextLine, func(t *testing.T) {
			body := "Pembayaran Berhasil\n\nPenerima\n" + nextLine + "\n\nTerima kasih.\n"
			decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
			if err != nil {
				t.Fatal(err)
			}
			parsed := ParseLivinNotification(decoded)
			if parsed.Status == "PARSED" {
				t.Fatalf("field line %q must not become a merchant label: %+v", nextLine, parsed)
			}
			if parsed.Reason != "merchant_missing" {
				t.Fatalf("reason = %q, want merchant_missing", parsed.Reason)
			}
		})
	}
}

// The date and time lines may have a reference line between them; the time must still be kept
// instead of silently parsing the date-only layout as midnight.
func TestParseLivinDateTimeWithInterveningField(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
No. Referensi ABC123XYZ
pkl 09:30:45 WIB
`
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		t.Fatalf("intervening field must not break parsing: %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 9, 30, 45, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

// WITA/WIT carry real UTC offsets; parsing them as Jakarta would shift the transaction time.
func TestParseLivinWitaTimezone(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
pkl 09:30:45 WITA
`
	decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseLivinNotification(decoded)
	if parsed.Status != "PARSED" {
		t.Fatalf("WITA template must parse: %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 9, 30, 45, 0, wita)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
	if parsed.EventAt.UTC().Equal(time.Date(2026, 11, 24, 9, 30, 45, 0, jakarta)) {
		t.Fatal("WITA must not be treated as WIB")
	}
}

// Short Indonesian month forms ("Nop", "Peb") appear in older templates.
func TestParseLivinShortIndonesianMonths(t *testing.T) {
	cases := map[string]time.Time{
		"5 Nop 2026": time.Date(2026, 11, 5, 9, 0, 0, 0, jakarta),
		"2 Peb 2026": time.Date(2026, 2, 2, 9, 0, 0, 0, jakarta),
	}
	for dateLine, want := range cases {
		t.Run(dateLine, func(t *testing.T) {
			body := "Pembayaran Berhasil\n\nPenerima\nWARUNG SEDERHANA\n\n" +
				"Nominal Transaksi Rp 25.000,00\nTanggal " + dateLine + "\npkl 09:00 WIB\n"
			decoded, err := DecodeMessage(rawEmail("Pembayaran Berhasil!", body))
			if err != nil {
				t.Fatal(err)
			}
			parsed := ParseLivinNotification(decoded)
			if parsed.Status != "PARSED" {
				t.Fatalf("short month %q must parse: %+v", dateLine, parsed)
			}
			if !parsed.EventAt.Equal(want) {
				t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
			}
		})
	}
}

// The inline "Penerima: value" path must apply the same field-value guard as the stacked path;
// otherwise an amount/date/reference prints as the merchant label.
func TestParseLivinInlineLabelRejectsFieldLines(t *testing.T) {
	for _, inlineValue := range []string{
		"Nominal Transaksi Rp 25.000,00",
		"24 Nov 2026",
		"No. Referensi ABC123XYZ",
	} {
		t.Run(inlineValue, func(t *testing.T) {
			body := `Pembayaran Berhasil

Penerima: ` + inlineValue + `
Jumlah: Rp 25.000
Tanggal: 10 Nov 2026 09:30:45
`
			parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
			if parsed.Status == "PARSED" {
				t.Fatalf("inline field %q must not become a merchant label: %+v", inlineValue, parsed)
			}
			if parsed.MerchantLabel != "" {
				t.Fatalf("merchant label = %q, want empty", parsed.MerchantLabel)
			}
		})
	}
}

// A business name may legitimately contain a month word and a street number; the guard must not
// turn it into merchant_missing.
func TestParseLivinMerchantWithMonthAndStreetNumber(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
TOKO MAJU 88 MEI

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
pkl 09:30:45 WIB
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("business name with month word must parse: %+v", parsed)
	}
	if parsed.MerchantLabel != "TOKO MAJU 88 MEI" {
		t.Fatalf("merchant = %q", parsed.MerchantLabel)
	}
}

// Some templates print the zone marker on its own line after the time.
func TestParseLivinSeparateZoneLine(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
pkl 09:30:45
WITA
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("separate zone line must parse: %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 9, 30, 45, 0, wita)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

// A time of day printed in the body two lines after the date but separated by ordinary prose
// (not a field line) must not be bound to the transaction.
func TestParseLivinIgnoresDistantTime(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
Promo berlaku hingga
23:59
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("date-only template must still parse: %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 0, 0, 0, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want date-only %s", parsed.EventAt, want)
	}
}

// A decorative divider between a stacked label and its value must not hide the merchant.
func TestParseLivinBareLabelSkipsSeparatorLine(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
------
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
pkl 09:30:45 WIB
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("separator line must not break parsing: %+v", parsed)
	}
	if parsed.MerchantLabel != "WARUNG SEDERHANA" {
		t.Fatalf("merchant = %q", parsed.MerchantLabel)
	}
}

// PAN/reference lines stacked under a business-name label must never be stored as the merchant.
func TestParseLivinStackedLabelRejectsPANAndFieldLines(t *testing.T) {
	for _, nextLine := range []string{
		"Merchant PAN: 936009110000123456",
		"Customer PAN: 936000110000654321",
		"Nomor Kartu 936009110000123456",
		"ID Transaksi 202611100001234567",
		"150.000,00",
		"Ref ABC123",
		"No Referensi ABC123",
		"ID 12345",
		"Kartu 1234",
	} {
		t.Run(nextLine, func(t *testing.T) {
			body := `Pembayaran Berhasil

Penerima
` + nextLine + `

Jumlah: Rp 25.000
Tanggal: 10 Nov 2026 09:30:45
`
			parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
			if parsed.Status == "PARSED" {
				t.Fatalf("field/PAN line %q must not become a merchant label: %+v", nextLine, parsed)
			}
			if parsed.MerchantLabel != "" {
				t.Fatalf("merchant label = %q, want empty", parsed.MerchantLabel)
			}
		})
	}
}

func TestParseLivinInlineLabelRejectsPANLine(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima: Merchant PAN: 936009110000123456
Jumlah: Rp 25.000
Tanggal: 10 Nov 2026 09:30:45
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status == "PARSED" || parsed.MerchantLabel != "" {
		t.Fatalf("inline PAN field must not become a merchant: %+v", parsed)
	}
}

// A business name may contain a short month word without a year ("Warung Bu Des 2").
func TestParseLivinMerchantWithShortMonthWord(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
Warung Bu Des 2

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
pkl 09:30:45 WIB
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("merchant with month word must parse: %+v", parsed)
	}
	if parsed.MerchantLabel != "Warung Bu Des 2" {
		t.Fatalf("merchant = %q", parsed.MerchantLabel)
	}
}

// Three field lines between the date and the time must still be crossed (production template).
func TestParseLivinTimeAcrossThreeFieldLines(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
No. Referensi ABC123XYZ
Merchant PAN: 936009110000123456
pkl 09:30:45 WIB
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("three intervening field lines must parse: %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 9, 30, 45, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want %s", parsed.EventAt, want)
	}
}

// Prose with a colon ("Catatan: simpan struk") is not a field line and must not bridge a time
// that sits two lines after the date.
func TestParseLivinProseColonDoesNotBridgeTime(t *testing.T) {
	body := `Pembayaran Berhasil

Penerima
WARUNG SEDERHANA

Nominal Transaksi Rp 25.000,00
Tanggal 24 Nov 2026
Catatan: simpan struk ini
pkl 09:30:45 WIB
`
	parsed := ParseLivinNotification(DecodedMessage{Subject: "Pembayaran Berhasil!", Text: body})
	if parsed.Status != "PARSED" {
		t.Fatalf("template must still parse: %+v", parsed)
	}
	want := time.Date(2026, 11, 24, 0, 0, 0, 0, jakarta)
	if !parsed.EventAt.Equal(want) {
		t.Fatalf("eventAt = %s, want date-only %s (prose must not bridge)", parsed.EventAt, want)
	}
}
