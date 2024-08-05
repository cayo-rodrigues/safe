package safe

import (
	"time"
	"unicode/utf8"
)

// A helper function. All provided arguments must have a valid value (meaning no zero values).
//
// Example usage:
//
//	fields := Fields{
//		{
//			Name:  "Ie",
//			Value: e.Ie,
//			Rules: safe.Rules(
//				safe.Match(safe.IEMGRegex),
//				safe.RequiredUnless(safe.All(e.PostalCode, e.Neighborhood, e.StreetType, e.StreetName, e.Number)),
//			),
//		},
//	}
//
// In the example above, Ie is required, unless all address info is provided.
//
// To achieve this, the safe.All helper function is used to return a boolean, indicating if
// all those values are valid non-zero values or not.
//
// Note that this is needed because safe.RequiredUnless satisfies its condition when at least one
// of its arguments have a value.
//
// On the other hand, with the use of safe.All, we ensure that all
// those address infos have a non-zero value.
func All(vals ...any) bool {
	for _, val := range vals {
		if !HasValue(val) {
			return false
		}
	}
	return true
}

// In safe, the concept of "having a value" is described as follows:
//
// - bool: it must be true.
// - string: it must have more than one rune (or character, if you will).
// - int, float64, float32: it must not be zero.
// - time.Time: it must not be the zero time instant, as prescribed by time.Time.IsZero.
func HasValue(val any) bool {
	switch val := val.(type) {
	case bool:
		return val
	case string:
		return utf8.RuneCountInString(val) > 0
	case int, float64, float32:
		return val != 0
	case time.Time:
		return !val.IsZero()
	}

	return false
}

// Given a list of values, all of them should be unique.
func AllUnique[T comparable](vals []T) bool {
	seen := make(map[T]struct{})
	for _, val := range vals {
		if _, exists := seen[val]; exists {
			return false
		}
		seen[val] = struct{}{}
	}

	return true
}
