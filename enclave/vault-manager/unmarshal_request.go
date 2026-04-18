package main

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/rs/zerolog/log"
)

// unmarshalRequest decodes a JSON request payload into `out` and, after
// decoding, cross-checks the raw JSON object against the set of JSON tag
// names declared on `out`. Any top-level key in the payload that doesn't
// correspond to a struct field gets a WARN log entry tagged with the
// operation name — the request is still accepted, so the vault stays
// forward-compatible with newer clients.
//
// Why this exists: silent field drops caused the "call never connects"
// bug we just fixed in calls.go. An app was sending `sdp_answer` on
// accept, but AcceptCallRequest didn't declare that field, so json's
// default behavior (ignore unknown fields) dropped it without a trace.
// Using Decoder.DisallowUnknownFields() instead would have failed the
// request hard — safe for catching bugs, bad for forward compat (any
// new field added client-side would break older vaults). Warn-and-
// accept is the balance: the bug surfaces in CloudWatch logs the first
// time it happens, but nothing in production breaks while the fix rolls
// out.
//
// Caller should replace `json.Unmarshal(msg.Payload, &req)` with
// `unmarshalRequest(msg.Payload, &req, "op_name")`.
func unmarshalRequest(data []byte, out interface{}, opName string) error {
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}

	// If the payload isn't a JSON object (e.g. empty array, null),
	// there's nothing to cross-check.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	known := jsonFieldNames(out)
	for key := range raw {
		if _, ok := known[key]; !ok {
			log.Warn().
				Str("op", opName).
				Str("unknown_field", key).
				Msg("vault request contains a top-level field not recognized by the target struct; ignoring")
		}
	}
	return nil
}

// jsonFieldNames returns the set of JSON names declared on the struct
// `v` (or the struct pointed to by `v`). Fields tagged `json:"-"` are
// skipped. Embedded struct fields are walked so their tags also count.
func jsonFieldNames(v interface{}) map[string]struct{} {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	names := make(map[string]struct{})
	if t.Kind() != reflect.Struct {
		return names
	}
	walkStructFields(t, names)
	return names
}

func walkStructFields(t reflect.Type, out map[string]struct{}) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			walkStructFields(f.Type, out)
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if tag == "" {
			// Untagged exported field — the unmarshaler matches by
			// field name; include it so we don't spurious-warn on
			// a valid-but-untagged request field.
			if f.IsExported() {
				out[f.Name] = struct{}{}
			}
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			out[name] = struct{}{}
		}
	}
}
