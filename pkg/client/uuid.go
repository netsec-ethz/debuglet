package client

import "errors"

// isCanonicalUUID reports whether s is the 36-character hyphenated hex
// spelling of a UUID in either hex case. Only these characters can appear in
// a validated ID, so an ID can never escape the base path.
func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isNilUUID reports whether a canonical UUID is all zeros.
func isNilUUID(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' && s[i] != '-' {
			return false
		}
	}
	return true
}

var errInvalidJobID = errors.New("client: invalid debuglet id: expected a canonical 36-character UUID")

// validateJobID rejects any caller-supplied job ID that is not a nonzero
// canonical UUID before it can be placed in a URL.
func validateJobID(id string) error {
	if !isCanonicalUUID(id) || isNilUUID(id) {
		return errInvalidJobID
	}
	return nil
}
