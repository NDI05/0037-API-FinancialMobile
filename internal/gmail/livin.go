package gmail

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Livin notification parsing.
//
// The parser is deliberately conservative: the merchant label must be the business name
// (`Penerima` first, then `Merchant`). A Merchant PAN, Customer PAN or reference number is an
// identifier, never a business name — the P0 bug this project already paid for. Anything it cannot
// prove becomes UNRESOLVED with a reason code so the import report stays honest.

// ParsedNotification is one notification after parsing. Reason is set only when Status is
// UNRESOLVED.
type ParsedNotification struct {
	Status        string
	Reason        string
	Direction     string
	AmountMinor   int64
	EventAt       time.Time
	MerchantLabel string
	Description   string
	Reference     string
}

// TemplateVersion identifies the parser generation stored with imported rows.
const TemplateVersion = "gmail-livin-v1"

var (
	jakarta = mustLoadJakarta()

	labelKeyPattern = regexp.MustCompile(`(?i)^(penerima|nama penerima|merchant|nama merchant|` +
		`toko|nama toko|biller|nama biller|merchant name|recipient)\s*[:\-]\s*(.+)$`)
	// labelBarePattern handles the production Livin layout where the label sits alone on its line
	// and the business name follows on the next line (no colon). Fixtures used inline labels; real
	// notification emails use the stacked form, so both must parse.
	labelBarePattern = regexp.MustCompile(`(?i)^(penerima|nama penerima|merchant|nama merchant|` +
		`toko|nama toko|biller|nama biller|merchant name|recipient)\s*:?\s*$`)
	amountPattern = regexp.MustCompile(`(?i)(?:jumlah|nominal|total(?:\s+pembayaran)?|amount|` +
		`nominal transaksi)\s*[:\-]?\s*(?:rp\.?\s*)?([0-9][0-9.,]*)`)
	standaloneAmountPattern = regexp.MustCompile(`(?i)rp\.?\s*([0-9][0-9.,]*)`)
	datePattern             = regexp.MustCompile(`(?i)(?:tanggal(?:\s*(?:&|dan)?\s*waktu)?|` +
		`waktu|transaction date|date)\s*[:\-]\s*(.+)$`)
	referencePattern = regexp.MustCompile(`(?i)(?:no\.?\s*referensi|nomor referensi|reference|` +
		`ref(?:erence)?\s*(?:no|number)?|no\.?\s*transaksi)\s*[:\-]?\s*([A-Za-z0-9.\-]{4,64})`)
	identifierPattern = regexp.MustCompile(`^[0-9][0-9 .\-/:]*$`)
	// dateLabelPattern strips the inline label words that travel with the date value in the
	// stacked production layout. Case-insensitive because production prints "Tanggal".
	dateLabelPattern = regexp.MustCompile(`(?i)\b(?:pkl\.?|tanggal|waktu|pukul)\b\s*`)
	// indonesianMonths maps the Indonesian month names/abbreviations used by production mail
	// ("12 Okt 2026", "5 Agustus 2026") to the English tokens the date layouts expect.
	indonesianMonths = regexp.MustCompile(`(?i)\b(januari|februari|maret|april|mei|juni|juli|` +
		`agustus|agu|agt|ags|september|oktober|okt|nopember|november|desember|des)\b`)

	dateLayouts = []string{
		"02 Jan 2006 15:04:05",
		"02 Jan 2006 15:04",
		"2 Jan 2006 15:04:05",
		"2 Jan 2006 15:04",
		"02 January 2006 15:04:05",
		"02 January 2006 15:04",
		"02 Jan 2006",
		"2 Jan 2006",
		"02/01/2006 15:04:05",
		"02/01/2006 15:04",
		"02-01-2006 15:04:05",
		"02-01-2006 15:04",
		"02/01/2006",
		"02-01-2006",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
		"02 Jan 2006 15:04 WIB",
		"02 Jan 2006 15:04:05 WIB",
	}
)

func mustLoadJakarta() *time.Location {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return time.FixedZone("Asia/Jakarta", 7*60*60)
	}
	return loc
}

// ParseLivinNotification turns a decoded email into a candidate. A non-Livin template is
// UNRESOLVED rather than silently skipped, so the import counters explain themselves.
func ParseLivinNotification(decoded DecodedMessage) ParsedNotification {
	lines := NormalizeLines(decoded.Subject + "\n" + decoded.Text)
	haystack := strings.ToLower(decoded.Subject + "\n" + decoded.Text)
	if !looksLikeLivin(haystack) {
		return ParsedNotification{Status: "UNRESOLVED", Reason: "template_unknown"}
	}
	result := ParsedNotification{
		Status:      "UNRESOLVED",
		Direction:   inferDirection(haystack),
		Description: truncate(sanitize(decoded.Subject), 200),
	}
	reference := ""
	if match := referencePattern.FindStringSubmatch(decoded.Subject + "\n" + decoded.Text); match != nil {
		reference = strings.TrimSpace(match[1])
		result.Reference = reference
	}
	merchant := findLabel(lines, reference)
	switch {
	case merchant == "":
		result.Reason = "merchant_missing"
	case isIdentifierLabel(merchant):
		result.Reason = "unsafe_merchant"
	default:
		result.MerchantLabel = sanitize(merchant)
	}
	amount, ok := findAmount(lines)
	if !ok {
		result.Reason = firstReason(result.Reason, "amount_missing")
	} else {
		result.AmountMinor = amount
	}
	eventAt, ok := findEventAt(lines)
	if !ok {
		result.Reason = firstReason(result.Reason, "event_time_missing")
	} else {
		result.EventAt = eventAt
	}
	if result.Reason == "" && result.MerchantLabel != "" && result.AmountMinor > 0 &&
		!result.EventAt.IsZero() {
		result.Status = "PARSED"
	}
	if result.Description == "" && result.MerchantLabel != "" {
		result.Description = truncate("Pembayaran ke "+result.MerchantLabel, 200)
	}
	return result
}

func looksLikeLivin(haystack string) bool {
	if strings.Contains(haystack, "livin") {
		return true
	}
	for _, marker := range []string{"pembayaran berhasil", "transaksi berhasil",
		"transfer berhasil", "pembayaran qris", "qris"} {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

func inferDirection(haystack string) string {
	for _, marker := range []string{"menerima", "diterima", "dana masuk", "transfer masuk",
		"uang masuk", "top up", "topup", "refund", "pengembalian dana"} {
		if strings.Contains(haystack, marker) {
			return "CREDIT"
		}
	}
	return "DEBIT"
}

// findLabel returns the business name, preferring Penerima over Merchant. Values that are only
// digits/separators are identifiers (PAN or reference) and are rejected.
func findLabel(lines []string, reference string) string {
	priority := map[string]int{
		"penerima": 1, "nama penerima": 1, "recipient": 1,
		"merchant": 2, "nama merchant": 2, "merchant name": 2,
		"toko": 3, "nama toko": 3, "biller": 3, "nama biller": 3,
	}
	bestRank := 99
	best := ""
	for index, line := range lines {
		key := ""
		value := ""
		if match := labelKeyPattern.FindStringSubmatch(line); match != nil {
			key = strings.ToLower(strings.TrimSpace(match[1]))
			value = strings.TrimSpace(match[2])
		} else if match := labelBarePattern.FindStringSubmatch(line); match != nil {
			key = strings.ToLower(strings.TrimSpace(match[1]))
			if index+1 < len(lines) {
				value = strings.TrimSpace(lines[index+1])
			}
		}
		if key == "" {
			continue
		}
		value = strings.Trim(value, " :-\t")
		if value == "" || isIdentifierLabel(value) || isReferenceValue(value, reference) ||
			labelBarePattern.MatchString(value) || labelKeyPattern.MatchString(value) {
			continue
		}
		if rank := priority[key]; rank < bestRank {
			bestRank = rank
			best = value
		}
	}
	return best
}

func isReferenceValue(value, reference string) bool {
	if reference == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(reference))
}

// isIdentifierLabel mirrors the app guard: a label made only of digits and separators is a PAN or
// reference number, not a business name.
func isIdentifierLabel(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	digits := 0
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == ' ' || r == '-' || r == '.' || r == '/' || r == ':':
		default:
			return false
		}
	}
	return digits >= 4
}

func findAmount(lines []string) (int64, bool) {
	for _, line := range lines {
		if match := amountPattern.FindStringSubmatch(line); match != nil {
			if value, ok := parseIDRAmount(match[1]); ok {
				return value, true
			}
		}
	}
	var candidates []int64
	for _, line := range lines {
		for _, match := range standaloneAmountPattern.FindAllStringSubmatch(line, -1) {
			if value, ok := parseIDRAmount(match[1]); ok {
				candidates = append(candidates, value)
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	return 0, false
}

// parseIDRAmount turns a printed rupiah amount into minor units. IDR has no circulating cents, so
// "25.000", "25.000,00" and "25,000.00" all become 25000. Ambiguous merges are rejected instead
// of guessed.
func parseIDRAmount(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimRight(raw, ".,")
	if raw == "" {
		return 0, false
	}
	hasDot := strings.Contains(raw, ".")
	hasComma := strings.Contains(raw, ",")
	switch {
	case hasDot && hasComma:
		// The separator that appears last is the decimal separator.
		if strings.LastIndex(raw, ",") > strings.LastIndex(raw, ".") {
			raw = strings.ReplaceAll(raw, ".", "")
			raw = strings.ReplaceAll(raw, ",", ".")
		} else {
			raw = strings.ReplaceAll(raw, ",", "")
		}
	case hasComma:
		parts := strings.Split(raw, ",")
		if len(parts) == 2 && len(parts[1]) == 2 {
			raw = parts[0] + "." + parts[1]
		} else {
			raw = strings.ReplaceAll(raw, ",", "")
		}
	case hasDot:
		parts := strings.Split(raw, ".")
		if len(parts) > 1 && len(parts[len(parts)-1]) == 2 {
			raw = strings.Join(parts[:len(parts)-1], "") + "." + parts[len(parts)-1]
		} else {
			raw = strings.ReplaceAll(raw, ".", "")
		}
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return 0, false
	}
	// Round to the nearest rupiah: a printed value with cents still has one real IDR amount.
	minor := int64(value)
	if minor <= 0 || minor > 1_000_000_000_000_000 {
		return 0, false
	}
	return minor, true
}

func findEventAt(lines []string) (time.Time, bool) {
	for _, line := range lines {
		match := datePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if parsed, ok := parseDateValue(match[1]); ok {
			return parsed, true
		}
	}
	// Production notifications stack the local time on the line after the date, e.g.
	// "Tanggal 24 Nov 2026" + "pkl 09:30:45 WIB". Joined pairs are tried before single lines so the
	// time is not lost to a date-only layout.
	for index := 0; index+1 < len(lines); index++ {
		joined := lines[index] + " " + lines[index+1]
		if len(strings.Fields(joined)) < 3 {
			continue
		}
		if parsed, ok := parseDateValue(joined); ok {
			return parsed, true
		}
	}
	for _, line := range lines {
		if parsed, ok := parseDateValue(line); ok {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func parseDateValue(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	// Label words and the short time marker travel with the value in the stacked production
	// layout ("Tanggal 24 Nov 2026 pkl 09:30:45 WIB"); drop them so the date layouts apply.
	raw = dateLabelPattern.ReplaceAllString(raw, "")
	raw = indonesianMonths.ReplaceAllStringFunc(raw, func(word string) string {
		switch strings.ToLower(word) {
		case "januari":
			return "Jan"
		case "februari":
			return "Feb"
		case "maret":
			return "Mar"
		case "april":
			return "Apr"
		case "mei":
			return "May"
		case "juni":
			return "Jun"
		case "juli":
			return "Jul"
		case "agustus", "agu", "agt", "ags":
			return "Aug"
		case "september":
			return "Sep"
		case "oktober", "okt":
			return "Oct"
		case "nopember", "november":
			return "Nov"
		case "desember", "des":
			return "Dec"
		default:
			return word
		}
	})
	for _, suffix := range []string{"WIB", "WIT", "WITA"} {
		raw = strings.ReplaceAll(raw, suffix, "")
	}
	raw = strings.Join(strings.Fields(raw), " ")
	for _, layout := range dateLayouts {
		if parsed, err := time.ParseInLocation(layout, raw, jakarta); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func firstReason(current, next string) string {
	if current != "" {
		return current
	}
	return next
}

func truncate(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	runes := []rune(raw)
	if len(runes) <= limit {
		return raw
	}
	return string(runes[:limit])
}
