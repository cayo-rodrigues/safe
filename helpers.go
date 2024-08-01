package safe

import (
	"time"
	"unicode/utf8"
)

func All(vals ...any) bool {
	for _, val := range vals {
		if !HasValue(val) {
			return false
		}
	}
	return true
}

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
	case time.Time:
		return !val.IsZero()
	}

	return false
}
