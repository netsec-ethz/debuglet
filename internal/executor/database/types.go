package database

import (
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CommaSeparatedList allows lists of strings to be stored in a single database column as a comma-separated string,
// with each string base64-encoded to handle special characters and commas within the strings themselves.
type CommaSeparatedList []string

func (b *CommaSeparatedList) Scan(src any) error {
	switch v := src.(type) {
	case string:
		if v == "" {
			*b = nil
			return nil
		}
		encoded := strings.Split(v, ",")
		decoded := make([]string, len(encoded))
		for i, s := range encoded {
			data, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("failed to decode base64 string: %w", err)
			}
			decoded[i] = string(data)
		}
		*b = decoded
	case []byte:
		return b.Scan(string(v))
	case nil:
		*b = nil
	default:
		return errors.New("unsupported type for CommaSeparatedList")
	}
	return nil
}

func (b CommaSeparatedList) Value() (driver.Value, error) {
	if len(b) == 0 {
		return nil, nil
	}
	encoded := make([]string, len(b))
	for i, s := range b {
		encoded[i] = base64.StdEncoding.EncodeToString([]byte(s))
	}
	return strings.Join(encoded, ","), nil
}

// UTCTime is a wrapper around time.Time that ensures the time is always stored and retrieved in UTC.
type UTCTime struct {
	time.Time
}

func NewUTCTime(t time.Time) UTCTime {
	return UTCTime{Time: t.UTC()}
}

func (t UTCTime) Value() (driver.Value, error) {
	if t.IsZero() {
		return nil, nil
	}
	return t.Time.UTC(), nil
}

func (t *UTCTime) Scan(src any) error {
	switch v := src.(type) {
	case time.Time:
		t.Time = v.UTC()
		return nil
	case string:
		parsed, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return err
		}
		t.Time = parsed.UTC()
		return nil
	case nil:
		t.Time = time.Time{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into UTCTime", src)
	}
}
