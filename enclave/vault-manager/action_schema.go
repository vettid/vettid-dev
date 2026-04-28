package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Tiny JSON-Schema validator covering the subset Phase-1 actions need:
//
//   - object with required + properties + additionalProperties:false
//   - string with minLength, maxLength
//   - integer with minimum, maximum
//   - array with items, minItems, maxItems
//   - enum (string values)
//
// We deliberately do NOT pull in github.com/santhosh-tekuri/jsonschema
// here — staying inside the enclave's audited dependency set, the
// validator below is ~150 lines and matches the action catalog's needs.
// If catalog growth makes this insufficient, swap in a vetted library.

// ValidateAgainstSchema runs schema (raw bytes) against value (raw
// bytes). Returns nil on success.
func ValidateAgainstSchema(schemaBytes, valueBytes []byte) error {
	var schema map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		return fmt.Errorf("schema parse: %w", err)
	}
	var value interface{}
	if len(valueBytes) > 0 {
		if err := json.Unmarshal(valueBytes, &value); err != nil {
			return fmt.Errorf("value parse: %w", err)
		}
	}
	return validateValue(schema, value, "")
}

func validateValue(schema map[string]interface{}, value interface{}, path string) error {
	if enumRaw, ok := schema["enum"]; ok {
		if enumList, ok := enumRaw.([]interface{}); ok {
			matched := false
			for _, e := range enumList {
				if e == value {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("%s: not in enum", path)
			}
		}
	}

	t, _ := schema["type"].(string)
	switch t {
	case "object":
		obj, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%s: expected object", path)
		}
		// required
		if reqRaw, ok := schema["required"]; ok {
			if reqList, ok := reqRaw.([]interface{}); ok {
				for _, r := range reqList {
					if rs, ok := r.(string); ok {
						if _, present := obj[rs]; !present {
							return fmt.Errorf("%s: missing required %q", path, rs)
						}
					}
				}
			}
		}
		// properties
		propsRaw, _ := schema["properties"].(map[string]interface{})
		if propsRaw != nil {
			for k, v := range obj {
				ps, ok := propsRaw[k].(map[string]interface{})
				if !ok {
					if addProp, found := schema["additionalProperties"].(bool); found && !addProp {
						return fmt.Errorf("%s: unexpected property %q", path, k)
					}
					continue
				}
				if err := validateValue(ps, v, path+"."+k); err != nil {
					return err
				}
			}
		} else if addProp, found := schema["additionalProperties"].(bool); found && !addProp {
			if len(obj) > 0 {
				return fmt.Errorf("%s: object should be empty", path)
			}
		}

	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: expected string", path)
		}
		if minLen, ok := schema["minLength"].(float64); ok && len(s) < int(minLen) {
			return fmt.Errorf("%s: shorter than minLength", path)
		}
		if maxLen, ok := schema["maxLength"].(float64); ok && len(s) > int(maxLen) {
			return fmt.Errorf("%s: longer than maxLength", path)
		}

	case "integer":
		// JSON numbers come in as float64; integers must be whole.
		f, ok := toFloat64(value)
		if !ok {
			return fmt.Errorf("%s: expected integer", path)
		}
		if f != float64(int64(f)) {
			return fmt.Errorf("%s: not an integer", path)
		}
		if min, ok := schema["minimum"].(float64); ok && f < min {
			return fmt.Errorf("%s: below minimum", path)
		}
		if max, ok := schema["maximum"].(float64); ok && f > max {
			return fmt.Errorf("%s: above maximum", path)
		}

	case "number":
		if _, ok := toFloat64(value); !ok {
			return fmt.Errorf("%s: expected number", path)
		}

	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: expected boolean", path)
		}

	case "array":
		arr, ok := value.([]interface{})
		if !ok {
			return fmt.Errorf("%s: expected array", path)
		}
		if minItems, ok := schema["minItems"].(float64); ok && len(arr) < int(minItems) {
			return fmt.Errorf("%s: fewer than minItems", path)
		}
		if maxItems, ok := schema["maxItems"].(float64); ok && len(arr) > int(maxItems) {
			return fmt.Errorf("%s: more than maxItems", path)
		}
		if itemsSchema, ok := schema["items"].(map[string]interface{}); ok {
			for i, v := range arr {
				if err := validateValue(itemsSchema, v, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}

	case "":
		// Type-less schema (e.g. parent provides only enum). Skip.
	default:
		// Unknown type — log-only-don't-fail-the-validation philosophy
		// would be wrong for security; reject unknown types.
		return fmt.Errorf("%s: unsupported schema type %q", path, t)
	}
	return nil
}

func toFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// pathOK is a convenience used by callers that just want a quick yes/no.
func pathOK(err error) bool { return err == nil }

// keep the linter happy if nothing else uses strings here
var _ = strings.Builder{}
