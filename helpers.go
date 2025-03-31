package safe

import (
	"strconv"
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

// A helper function. All provided arguments must satisfy f(val).
func AllFunc(f func(any) bool, vals ...any) bool {
	for _, val := range vals {
		if !f(val) {
			return false
		}
	}
	return true
}

// A helper function. None of the provided arguments should have a valid value (meaning they should all be zero values).
//
// Exactly the opposite of safe.All.
//
// Here is an example of how it might be used:
//
//	fields := Fields{
//		{
//			Name:  "Ie",
//			Value: e.Ie,
//			Rules: safe.Rules(
//				safe.Match(safe.IEMGRegex),
//				safe.RequiredIf(safe.None(e.PostalCode, e.Neighborhood, e.StreetType, e.StreetName, e.Number)),
//			),
//		},
//	}
//
// In the example above, Ie is required only when none of the address fields have a value.
//
// In essence, we are achieving the same behavior of the example in the safe.All docs.
func None(vals ...any) bool {
	for _, val := range vals {
		if HasValue(val) {
			return false
		}
	}
	return true
}

// A helper function. None of the provided arguments should satisfy f(val).
func NoneFunc(f func(any) bool, vals ...any) bool {
	for _, val := range vals {
		if f(val) {
			return false
		}
	}
	return true
}

// A helper function. At least one of the provided arguments must have a valid value (meaning no zero values).
func Some(vals ...any) bool {
	for _, val := range vals {
		if HasValue(val) {
			return true
		}
	}
	return false
}

// A helper function. At least one of the provided arguments must satisfy f(val).
func SomeFunc(f func(any) bool, vals ...any) bool {
	for _, val := range vals {
		if f(val) {
			return true
		}
	}
	return false
}

// In safe, the concept of "having a value" is described as follows:
//
//	bool: it must be true.
//
//	string: it must have more than one rune (or character, if you will).
//
//	int, float64, float32: it must not be zero.
//
//	time.Time: it must not be the zero time instant, as prescribed by time.Time.IsZero.
//
//	struct{}: empty structs are not considered as "having a value"
//
//	anything else: is not nil
func HasValue(val any) bool {
	switch val := val.(type) {
	case bool:
		return val
	case string:
		return utf8.RuneCountInString(val) > 0
	case int:
		return val != 0
	case float64:
		return val != 0
	case float32:
		return val != 0
	case time.Time:
		return !val.IsZero()
	case struct{}:
		return false
	default:
		return val != nil
	}
}

// Exactly the same as safe.HasValue, but skip numeric values.
//
// This means that zero is a valid number
func HasValue__SkipNumeric(val any) bool {
	switch val := val.(type) {
	case int:
		return true
	case float64:
		return true
	case float32:
		return true
	default:
		return HasValue(val)
	}
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

// A helper function to determine if a password is considered strong.
//
// This means 8+ characters, with lowercase and uppercase letters, numbers and special characters.
func IsStrongPassword(password string) bool {
	if utf8.RuneCountInString(password) < 8 {
		return false
	}

	hasUppercase := HasUppercaseRegex.MatchString
	hasLowercase := HasLowercaseRegex.MatchString
	hasDigit := HasDigitRegex.MatchString
	hasSpecial := HasSpecialCharacterRegex.MatchString

	return hasUppercase(password) && hasLowercase(password) && hasDigit(password) && hasSpecial(password)
}

// A helper function to calculate the difference in days of two datetime values.
//
// Please note that this function will completely ignore the hours, minutes, seconds and so on.
// It will purely considerer the days.
//
// The order of the arguments does not matter, and which one comes first or last in time does not matter as well.
func DifferenceInDays(dt1, dt2 time.Time) int {
	year1, month1, day1 := dt1.Date()
	year2, month2, day2 := dt2.Date()
	date1 := time.Date(year1, month1, day1, 0, 0, 0, 0, dt1.Location())
	date2 := time.Date(year2, month2, day2, 0, 0, 0, 0, dt2.Location())
	diff := date1.Sub(date2)
	if diff < 0 {
		diff = -diff
	}
	return int(diff.Hours() / 24)
}

// A helper function to convert a value of type any to a float64
//
// This can be used in validation functions to easily validate number fields
func AnyToFloat64(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
