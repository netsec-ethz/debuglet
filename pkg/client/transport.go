package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// maxSuccessBody bounds a successful JSON response; larger bodies are a
	// clear size error, never a truncated decode.
	maxSuccessBody = 4 << 20
	// maxErrorBody bounds the message read from an unexpected response.
	maxErrorBody = 8 << 10
	// unsafeErrorMessage replaces response envelopes that cannot safely be
	// interpreted as a diagnostic.
	unsafeErrorMessage = "response body omitted"
	// maxCodeLength bounds an accepted failure code.
	maxCodeLength = 64
)

// protocolError reports a response with the expected status whose body does
// not satisfy the route's contract (malformed or trailing JSON, missing or
// invalid fields, oversized body). It never carries request data.
type protocolError struct {
	method string
	path   string
	msg    string
}

func (e *protocolError) Error() string {
	return fmt.Sprintf("client: %s %s: invalid response: %s", e.method, e.path, e.msg)
}

// path returns the request path (base path plus route, no query) for a route.
func (c *Client) path(route string) string {
	return c.basePath + "/" + route
}

func (c *Client) protocolErr(method, route, msg string) error {
	return &protocolError{method: method, path: c.path(route), msg: msg}
}

// do performs one request bounded by ctx and the per-request timeout, closes
// the response body and returns the bounded body bytes when the status is the
// expected one. Any other status becomes an *HTTPError. Nothing is retried.
func (c *Client) do(ctx context.Context, method, route string, query url.Values, body []byte, want int, secrets ...string) ([]byte, error) {
	if c == nil || c.http == nil {
		return nil, errors.New("client: Client must be created with New")
	}
	path := c.path(route)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	target := c.origin + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(apiVersionHeader, APIVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.credential != "" {
		// The credential goes only to this client's own origin: the request
		// target is built from it and redirects are refused. It is also added
		// to the redacted values, so no diagnostic can echo it back.
		req.Header.Set("Authorization", "Bearer "+c.credential)
		secrets = append(secrets, c.credential)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapTransport(ctx, method, path, err, secrets...)
	}
	defer resp.Body.Close()

	if resp.StatusCode != want {
		data, exceeded, readErr := readBounded(resp.Body, maxErrorBody)
		if readErr != nil && ctx.Err() != nil {
			return nil, wrapTransport(ctx, method, path, readErr, secrets...)
		}
		code, message := extractError(data, exceeded || readErr != nil, secrets...)
		return nil, &HTTPError{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Code:       code,
			Message:    message,
		}
	}
	if want == http.StatusNoContent {
		return nil, nil
	}
	data, exceeded, readErr := readBounded(resp.Body, maxSuccessBody)
	if readErr != nil {
		return nil, wrapTransport(ctx, method, path, fmt.Errorf("reading response body: %w", readErr), secrets...)
	}
	if exceeded {
		return nil, &protocolError{method: method, path: path, msg: "response body exceeds 4 MiB"}
	}
	return data, nil
}

// wrapTransport wraps a transport or read failure so that the method and safe
// path are visible and errors.Is still finds context cancellation/deadlines,
// including when the transport reported the cancellation in its own words.
// The diagnostic is sanitized; explicitly unwrapping retains original errors.
func wrapTransport(ctx context.Context, method, path string, err error, secrets ...string) error {
	original := err
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	var message string
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		original = errors.Join(cerr, original)
		message = fmt.Sprintf("client: %s %s: %v (%v)", method, path, cerr, err)
	} else {
		message = fmt.Sprintf("client: %s %s: %v", method, path, err)
	}
	return &transportError{message: redactSecrets(message, secrets), err: original}
}

type transportError struct {
	message string
	err     error
}

func (e *transportError) Error() string { return e.message }
func (e *transportError) Unwrap() error { return e.err }

// readBounded reads at most limit bytes and reports whether more were
// available.
func readBounded(r io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	exceeded := int64(len(data)) > limit
	if exceeded {
		data = data[:limit]
	}
	return data, exceeded, err
}

// extractError derives the failure code and a safe diagnostic without falling
// back to entire JSON envelopes. Credential fields are removed before
// selecting a message; their values, and any known submission key, are
// redacted from the result. The code is accepted only as a bounded identifier,
// so no response text can reach the caller through it.
func extractError(data []byte, incomplete bool, secrets ...string) (code, message string) {
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") || strings.HasPrefix(text, "\"") {
		if incomplete {
			return "", unsafeErrorMessage
		}
		dec := json.NewDecoder(strings.NewReader(text))
		dec.UseNumber()
		value, err := diagnosticJSON(dec, &secrets)
		if err != nil {
			return "", unsafeErrorMessage
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return "", unsafeErrorMessage
		}
		switch v := value.(type) {
		case map[string]any:
			if declared, ok := v["code"].(string); ok {
				code = safeCode(redactSecrets(declared, secrets))
			}
			reported, ok := v["message"]
			if !ok {
				// A code without a message is still an actionable failure;
				// only the diagnostic is missing.
				return code, unsafeErrorMessage
			}
			if s, ok := reported.(string); ok {
				text = s
			} else {
				encoded, err := json.Marshal(reported)
				if err != nil {
					return code, unsafeErrorMessage
				}
				text = string(encoded)
			}
		case string:
			text = v
		default:
			return "", unsafeErrorMessage
		}
	}
	text = redactSecrets(text, secrets)
	text = strings.ToValidUTF8(text, "�")
	if len(text) > maxErrorBody {
		text = text[:maxErrorBody]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return code, strings.TrimSpace(text)
}

// safeCode accepts a reported failure code only in the documented shape: a
// short lowercase identifier. Anything else, including a redacted value, is
// dropped rather than exposed as a code.
func safeCode(reported string) string {
	if reported == "" || len(reported) > maxCodeLength {
		return ""
	}
	for i := 0; i < len(reported); i++ {
		c := reported[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return ""
		}
	}
	return reported
}

// diagnosticJSON decodes a bounded JSON value while removing credential
// fields. Token traversal retains credentials from duplicate auth_key fields
// too, so a later duplicate cannot hide a key echoed in the selected message.
func diagnosticJSON(dec *json.Decoder, secrets *[]string) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, err
			}
			value, err := diagnosticJSON(dec, secrets)
			if err != nil {
				return nil, err
			}
			name := key.(string) // A decoder token in object-key position is a string.
			if strings.EqualFold(name, "auth_key") {
				if s, ok := value.(string); ok && s != "" {
					*secrets = append(*secrets, s)
				}
				continue
			}
			object[name] = value
		}
		_, err := dec.Token() // closing brace
		return object, err
	case json.Delim('['):
		array := make([]any, 0)
		for dec.More() {
			value, err := diagnosticJSON(dec, secrets)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := dec.Token() // closing bracket
		return array, err
	default:
		return token, nil
	}
}

func redactSecrets(text string, secrets []string) string {
	var values []string
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		values = append(values, secret, strings.ToValidUTF8(secret, "�"))
		// Object/array messages are re-encoded, so their key may be escaped.
		encoded, _ := json.Marshal(secret)
		values = append(values, string(encoded[1:len(encoded)-1]))
		// HTTP parser and custom transport errors may use Go's %q, whose
		// escaping differs from JSON (for example control bytes and HTML).
		for _, quoted := range []string{strconv.Quote(secret), strconv.QuoteToASCII(secret)} {
			values = append(values, quoted[1:len(quoted)-1])
		}
	}
	// Longest first prevents a shorter key from hiding part of another key.
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	replacements := make([]string, 0, 2*len(values))
	for _, value := range values {
		replacements = append(replacements, value, "[redacted]")
	}
	if len(replacements) == 0 {
		return text
	}
	return strings.NewReplacer(replacements...).Replace(text)
}

// decode parses one JSON value from a successful body, rejecting malformed
// or trailing data while ignoring unknown fields.
func (c *Client) decode(method, route string, data []byte, v any) error {
	if err := decodeStrict(data, v); err != nil {
		return &protocolError{method: method, path: c.path(route), msg: err.Error()}
	}
	return nil
}

// decodeStrict decodes exactly one JSON value; anything after it is an error.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty body")
		}
		// Decoder errors can quote response values (for example an invalid
		// numeric field), so expose only the category, never those values.
		return errors.New("malformed JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// marshalJSON encodes a request body.
func marshalJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("client: encoding request: %w", err)
	}
	return data, nil
}
