package gmail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

// DecodedMessage is the in-memory view of one notification email. It is intentionally small: the
// coordinator uses it to build import candidates and then drops the raw bytes.
type DecodedMessage struct {
	Subject string
	From    string
	Text    string
}

// DecodeMessage walks a raw RFC 822 message and returns the best text body. Only text/plain and
// text/html are considered; attachments and inline images are ignored. The raw payload never
// leaves this function's caller.
func DecodeMessage(raw []byte) (DecodedMessage, error) {
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return DecodedMessage{}, fmt.Errorf("read message: %w", err)
	}
	decoded := DecodedMessage{
		Subject: decodeHeader(parsed.Header.Get("Subject")),
		From:    decodeHeader(parsed.Header.Get("From")),
	}
	contentType := parsed.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	plain, htmlBody := extractParts(parsed.Header, parsed.Body, contentType, 0)
	if strings.TrimSpace(plain) != "" {
		decoded.Text = plain
	} else {
		decoded.Text = htmlToText(htmlBody)
	}
	return decoded, nil
}

func extractParts(header mail.Header, body io.Reader, contentType string, depth int) (string, string) {
	if depth > 4 {
		return "", ""
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return "", ""
		}
		reader := multipart.NewReader(body, boundary)
		var plain, htmlBody strings.Builder
		for {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			partType := part.Header.Get("Content-Type")
			partPlain, partHTML := extractParts(mail.Header(part.Header), part, partType, depth+1)
			plain.WriteString(partPlain)
			htmlBody.WriteString(partHTML)
			_ = part.Close()
		}
		return plain.String(), htmlBody.String()
	}
	if strings.HasPrefix(mediaType, "text/plain") {
		return decodeTransfer(body, header.Get("Content-Transfer-Encoding")), ""
	}
	if strings.HasPrefix(mediaType, "text/html") {
		return "", decodeTransfer(body, header.Get("Content-Transfer-Encoding"))
	}
	return "", ""
}

func decodeTransfer(body io.Reader, encoding string) string {
	var reader io.Reader = body
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		reader = quotedprintable.NewReader(body)
	}
	limited, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		return ""
	}
	if !utf8.Valid(limited) {
		return strings.ToValidUTF8(string(limited), "?")
	}
	return string(limited)
}

func decodeHeader(raw string) string {
	if decoded, err := (&mime.WordDecoder{}).DecodeHeader(raw); err == nil {
		return strings.TrimSpace(decoded)
	}
	return strings.TrimSpace(raw)
}

var (
	htmlBreakPattern = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr)\s*/?\s*>`)
	htmlTagPattern   = regexp.MustCompile(`(?s)<[^>]*>`)
	multiSpace       = regexp.MustCompile(`[ \t]+`)
)

func htmlToText(raw string) string {
	text := htmlBreakPattern.ReplaceAllString(raw, "\n")
	text = htmlTagPattern.ReplaceAllString(text, " ")
	text = html.UnescapeString(text)
	return text
}

// NormalizeLines collapses the visual layout of an email into one `key: value` per line. It is
// shared by the Livin parser and its tests so a layout change is a single edit.
func NormalizeLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = multiSpace.ReplaceAllString(sanitize(line), " ")
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// sanitize removes control characters that would corrupt a stored label or log line.
func sanitize(raw string) string {
	var builder strings.Builder
	for _, r := range raw {
		switch {
		case r == '\t' || r == '\n':
			builder.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			continue
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
