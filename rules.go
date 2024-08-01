package safe

import (
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// A safe.RuleSet is what actually validates a value agains a validate func (a "rule" if you will).
//
// It also is responsible for providing error messages thourgh a message func.
//
// Usualy, safe.RuleSets are not used directly.
//
// Instead, it is preffered to use safe.RuleFuncs (which is simply a func that returns *safe.RuleSet), like the ones exposed by this library.
type RuleSet struct {
	FieldValue   any
	MessageFunc  func(*RuleSet) string
	ValidateFunc func(*RuleSet) bool
}

// Modifies a default message from a RuleSet, effectively letting you provide your own custom error messages.
//
// Example usage:
//
//	fields := Fields{
//		{
//			Name:  "Username",
//			Value: u.Username,
//			Rules: Rules(Required().WithMessage("Why did you leave it blank?")),
//		},
//	}
func (rs *RuleSet) WithMessage(msg string) RuleFunc {
	rs.MessageFunc = func(rs *RuleSet) string {
		return msg
	}

	return func() *RuleSet {
		return rs
	}
}

// You can make your own RuleFuncs.
//
// Look at the source code of safe.Required, safe.Email, safe.Max or safe.OneOf. It's not so complicated.
type RuleFunc func() *RuleSet

// Calls each of the provided RuleFuncs and returns the resulting RuleSets.
func Rules(ruleFuncs ...RuleFunc) []*RuleSet {
	ruleSets := make([]*RuleSet, len(ruleFuncs))
	for i := 0; i < len(ruleSets); i++ {
		ruleSets[i] = ruleFuncs[i]()
	}

	return ruleSets
}

// The field must have a value. Zero values are not allowed, except for boolean fields.
//
// Supported field types: bool, string, int, float64, float32, time.Time
//
// Example:
//
//	u := &User{Username: "", BooleanField: false}
//
//	fields := Fields{
//		{
//			Name:  "Username",
//			Value: u.Username,
//			Rules: Rules(Required),
//		},
//		{
//			Name:  "BooleanField",
//			Value: u.BooleanField,
//			Rules: Rules(Required),
//		},
//	}
//	errors, ok := Validate(fields)
//
// In the example above, username field will not be valid, but the boolean field is valid,
// because it has a value. In essence, safe.Required bypasses boolean fields.
//
// To validate boolean fields more specificaly, use safe.True and safe.False.
func Required() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return MandatoryFieldMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			return HasValue(rs.FieldValue)
		},
	}
}

func True() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return MandatoryFieldMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			boolean, ok := rs.FieldValue.(bool)
			if !ok {
				return false
			}
			return boolean == true
		},
	}
}

func False() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return MandatoryFieldMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			boolean, ok := rs.FieldValue.(bool)
			if !ok {
				return false
			}
			return boolean == false
		},
	}
}

func Email() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return EmailRegex.MatchString(str)
		},
	}
}

func Phone() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return PhoneRegex.MatchString(str)
		},
	}
}

func Cpf() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CpfRegex.MatchString(str)
		},
	}
}

func Cnpj() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CnpjRegex.MatchString(str)
		},
	}
}

func CpfCnpj() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CpfRegex.MatchString(str) || CnpjRegex.MatchString(str)
		},
	}
}

func CEP() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CepRegex.MatchString(str)
		},
	}
}

func StrongPassword() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return ""
		},
		ValidateFunc: func(rs *RuleSet) bool {
			pwd, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if pwd == "" {
				return true
			}

			return StrongPasswordRegex.MatchString(pwd)
		},
	}
}

func UniqueList[T string | int]() *RuleSet {
	return &RuleSet{
		MessageFunc: func(rs *RuleSet) string {
			return UniqueListMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			vals, ok := rs.FieldValue.([]T)
			if !ok {
				return false
			}

			if len(vals) == 0 {
				return true
			}

			var previousVal T
			for _, val := range vals {
				if val == previousVal {
					return false
				}
				previousVal = val
			}

			return true
		},
	}
}

func Match(regexes ...*regexp.Regexp) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return InvalidFormatMsg
			},
			ValidateFunc: func(rs *RuleSet) bool {
				str, ok := rs.FieldValue.(string)
				if !ok {
					return false
				}

				if str == "" {
					return true
				}

				for _, regex := range regexes {
					match := regex.MatchString(str)
					if match {
						return true
					}
				}

				return false
			},
		}
	}
}

func MatchList(regexes ...*regexp.Regexp) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return InvalidFormatMsg
			},
			ValidateFunc: func(rs *RuleSet) bool {
				if rs.FieldValue == nil {
					return true
				}

				vals, ok := rs.FieldValue.([]string)
				if !ok {
					return false
				}

				if len(vals) == 0 {
					return true
				}

				for _, val := range vals {
					for _, regex := range regexes {
						match := regex.MatchString(val)
						if !match {
							return false
						}
					}
				}

				return true
			},
		}
	}
}

func Min(minValue int) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				switch rs.FieldValue.(type) {
				case int, float32, float64:
					return fmt.Sprintf("Valor mínimo: %d", minValue)
				default:
					return fmt.Sprintf("Mínimo de %d caracteres", minValue)
				}
			},
			ValidateFunc: func(rs *RuleSet) bool {
				switch val := rs.FieldValue.(type) {
				case int:
					return val >= minValue
				case float64:
					return val >= float64(minValue)
				case float32:
					return val >= float32(minValue)
				case string:
					if val == "" {
						return true
					}
					return utf8.RuneCountInString(val) >= minValue
				}

				return false
			},
		}
	}
}

func Max(maxValue int) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				switch rs.FieldValue.(type) {
				case int, float32, float64:
					return fmt.Sprintf("Valor máximo: %d", maxValue)
				default:
					return fmt.Sprintf("Máximo de %d caracteres", maxValue)
				}
			},
			ValidateFunc: func(rs *RuleSet) bool {
				switch val := rs.FieldValue.(type) {
				case int:
					return val <= maxValue
				case string:
					if val == "" {
						return true
					}
					return utf8.RuneCountInString(val) <= maxValue
				}

				return false
			},
		}
	}
}

func OneOf[T string | int | float64 | float32](vals []T) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return UnacceptableValueMsg
			},
			ValidateFunc: func(rs *RuleSet) bool {
				for _, val := range vals {
					if val == rs.FieldValue {
						return true
					}
				}
				return false
			},
		}
	}
}

func NotOneOf[T string | int | float64 | float32](vals []T) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return UnacceptableValueMsg
			},
			ValidateFunc: func(rs *RuleSet) bool {
				for _, val := range vals {
					if val == rs.FieldValue {
						return false
					}
				}
				return true
			},
		}
	}
}

func RequiredUnless(vals ...any) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return MandatoryFieldMsg
			},
			ValidateFunc: func(rs *RuleSet) bool {
				if HasValue(rs.FieldValue) {
					return true
				}
				for _, val := range vals {
					if HasValue(val) {
						return true
					}
				}
				return false
			},
		}
	}
}

func NotAfter(dt time.Time) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return IlogicalDatesMsg
			},
			ValidateFunc: func(rs *RuleSet) bool {
				switch val := rs.FieldValue.(type) {
				case time.Time:
					return !val.After(dt)
				}

				return false
			},
		}
	}
}

func MaxDaysRange(dt time.Time, maxDays int) RuleFunc {
	return func() *RuleSet {
		return &RuleSet{
			MessageFunc: func(rs *RuleSet) string {
				return fmt.Sprintf("Período não pode ser maior que %d dias", maxDays)
			},
			ValidateFunc: func(rs *RuleSet) bool {
				switch val := rs.FieldValue.(type) {
				case time.Time:
					diffInDays := int(dt.Sub(val).Hours() / 24)
					return diffInDays <= maxDays
				}

				return false
			},
		}
	}
}
