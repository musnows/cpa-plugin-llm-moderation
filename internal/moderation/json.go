package moderation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Reject duplicate fields so the moderator and the upstream cannot interpret different values.
func DecodeJSON(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return json.Unmarshal(raw, dst)
}

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 100 {
		return errors.New("JSON nesting limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err = d.Token()
			key, ok := t.(string)
			if err != nil || !ok || seen[key] {
				return errors.New("invalid or duplicate JSON field")
			}
			seen[key] = true
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}
