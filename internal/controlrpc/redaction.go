package controlrpc

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/status"
)

// A peer can reflect its credential in an otherwise useful operational error.
// Keep unrelated diagnostics and status codes. A sanitized error contains only
// the reconstructed safe status, never a token-bearing wrapped original.
func (c Credentials) RedactError(err error) error {
	if err == nil {
		return nil
	}
	raw := string(c.Token[:])
	quotedJSON, _ := json.Marshal(raw)
	variants := []string{
		raw, base64.RawURLEncoding.EncodeToString(c.Token[:]), base64.URLEncoding.EncodeToString(c.Token[:]),
		base64.RawStdEncoding.EncodeToString(c.Token[:]), base64.StdEncoding.EncodeToString(c.Token[:]),
		hex.EncodeToString(c.Token[:]), strings.ToUpper(hex.EncodeToString(c.Token[:])),
		strconv.Quote(raw), strconv.QuoteToASCII(raw), string(quotedJSON), fmt.Sprint(c.Token[:]),
	}
	// Escaped inner text may appear without its surrounding string quotes.
	for _, quoted := range []string{strconv.Quote(raw), strconv.QuoteToASCII(raw), string(quotedJSON)} {
		variants = append(variants, quoted[1:len(quoted)-1])
	}
	redact := func(text string) (string, bool) {
		changed := false
		for _, secret := range variants {
			if secret != "" && strings.Contains(text, secret) {
				text = strings.ReplaceAll(text, secret, "[redacted]")
				changed = true
			}
		}
		return text, changed
	}
	_, changed := redact(err.Error())
	st := status.Convert(err)
	projected := st.Proto()
	var messageChanged bool
	projected.Message, messageChanged = redact(projected.Message)
	changed = changed || messageChanged
	details := projected.Details[:0]
	for _, detail := range projected.Details {
		_, typeSecret := redact(detail.GetTypeUrl())
		_, valueSecret := redact(string(detail.GetValue()))
		if typeSecret || valueSecret {
			changed = true
			continue
		}
		details = append(details, detail)
	}
	projected.Details = details
	if !changed {
		return err
	}
	return status.FromProto(projected).Err()
}
