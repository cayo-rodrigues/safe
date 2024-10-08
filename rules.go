package safe

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type Rules []*RuleSet

func (r Rules) String() string {
	ruleNames := &strings.Builder{}
	for i, rule := range r {
		ruleNames.WriteString(rule.String())

		isLastIteration := i == len(r)-1
		if !isLastIteration {
			ruleNames.WriteString(", ")
		}
	}

	return ruleNames.String()
}

// A safe.RuleSet is what actually validates a value agains a validate func (a "rule" if you will).
//
// It is also responsible for providing error messages thourgh a message func.
//
// Usualy, safe.RuleSet is not used directly.
//
// This library exposes functions that return a *safe.RuleSet. You can also make your own!
type RuleSet struct {
	RuleName     string
	FieldValue   any
	MessageFunc  func(*RuleSet) string
	ValidateFunc func(*RuleSet) bool
}

// Modifies a default message from a RuleSet, effectively letting you provide your own custom error messages.
//
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name:  "Username",
//			Value: u.Username,
//			Rules: safe.Rules{safe.Required().WithMessage("Why did you leave it blank?")},
//		},
//	}
func (rs *RuleSet) WithMessage(msg string) *RuleSet {
	rs.MessageFunc = func(rs *RuleSet) string {
		return msg
	}

	return rs
}

func (rs *RuleSet) String() string {
	return rs.RuleName
}

// The field must have a value. Zero values are not allowed, except for boolean fields.
//
// Supported field types: bool, string, int, float64, float32, time.Time
//
// Example:
//
//	u := &User{Username: "", BooleanField: false}
//
//	fields := safe.Fields{
//		{
//			Name:  "Username",
//			Value: u.Username,
//			Rules: safe.Rules{safe.Required()},
//		},
//		{
//			Name:  "BooleanField",
//			Value: u.BooleanField,
//			Rules: safe.Rules{safe.Required()},
//		},
//	}
//	errors, ok := safe.Validate(fields)
//
// In the example above, username field will not be valid, but the boolean field is valid,
// because it has a value. In essence, safe.Required bypasses boolean fields.
//
// To validate boolean fields more specificaly, use safe.True and safe.False.
func Required() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Required",
		MessageFunc: func(rs *RuleSet) string {
			return MandatoryFieldMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			return HasValue(rs.FieldValue)
		},
	}
}

// The field must be a bool with value of true
func True() *RuleSet {
	return &RuleSet{
		RuleName: "safe.True",
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

// The field must be a bool with value of false
func False() *RuleSet {
	return &RuleSet{
		RuleName: "safe.False",
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

// The field must be a string with a valid email format
func Email() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Email",
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

// The field must be a string with a valid phone format.
//
// It may or may not include symbols (like +, - and ())
// or whitespaces
func Phone() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Phone",
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

// The field must be a string with a valid cpf format
//
// It may or may not include symbols
func Cpf() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Cpf",
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

// The field must be a string with a valid cnpj format
//
// It may or may not include symbols
func Cnpj() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Cnpj",
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

// The field must be a string with a valid cpf or cnpj format
//
// It may or may not include symbols
func CpfCnpj() *RuleSet {
	return &RuleSet{
		RuleName: "safe.CpfCnpj",
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

// The field must be a string with a valid cep format
func CEP() *RuleSet {
	return &RuleSet{
		RuleName: "safe.CEP",
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

// The field must be a string with a strong password pattern.
//
// This means 8+ characters, with lowercase and uppercase letters, numbers and special characters.
func StrongPassword() *RuleSet {
	return &RuleSet{
		RuleName: "safe.StrongPassword",
		MessageFunc: func(rs *RuleSet) string {
			return WeakPasswordMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			pwd, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if pwd == "" {
				return true
			}

			return IsStrongPassword(pwd)
		},
	}
}

// The field must be a string with a valid format for a uuid v1, v4, v5 or v7.
//
// In case you are using a uuid package like google's, you will likely
// not need this, because you will already have a uuid validation method.
//
// Besides that, most of the time the database itself will generate the uuids.
func UUIDstr() *RuleSet {
	return &RuleSet{
		RuleName: "safe.UUIDstr",
		MessageFunc: func(rs *RuleSet) string {
			return InvalidFormatMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			uuid, ok := rs.FieldValue.(string)
			if !ok {
				return false
			}

			if uuid == "" {
				return true
			}

			return UUIDRegex.MatchString(uuid)
		},
	}
}

// The field must be a slice of values, each of them implementing the comparable interface.
// All values in the list should be unique.
//
// Must provide type inference.
//
// Example usage:
//
//	someList := [6]string{"q", "w", "e", "q", "t", "y"}
//
//	fields := safe.Fields{
//		{
//			Name:  "fieldName",
//			Value: someList,
//			Rules: safe.Rules{safe.Required(), safe.UniqueList[string]()},
//		},
//	}
//
// IMPORTANT!
//
// Please note that if you pass "any" as type parameter to safe.UniqueList, it will
// work **only** with explicit []any types. If you pass another type, there will be runtime errors.
func UniqueList[T comparable]() *RuleSet {
	return &RuleSet{
		RuleName: "safe.UniqueList",
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

			return AllUnique(vals)
		},
	}
}

// The field must be a string that matches all the given regexes.
func Match(regexes ...*regexp.Regexp) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Match",
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

// The field must be a slice of string, in which all strings match all the given regexes.
func MatchList(regexes ...*regexp.Regexp) *RuleSet {
	return &RuleSet{
		RuleName: "safe.MatchList",
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

// The field must be an int, float64, float32 or string.
//
// In case it is a numeric value, it must not be less then minValue.
//
// As for strings, they must not have less then minValue number of characters.
func Min(minValue int) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Min",
		MessageFunc: func(rs *RuleSet) string {
			switch rs.FieldValue.(type) {
			case int, float32, float64:
				return MinValueMsg(minValue)
			default:
				return MinCharsMsg(minValue)
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

// The field must be an int, float64, float32 or string.
//
// In case it is a numeric value, it must not greater then maxValue.
//
// As for strings, they must not have more then maxValue number of characters.
func Max(maxValue int) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Max",
		MessageFunc: func(rs *RuleSet) string {
			switch rs.FieldValue.(type) {
			case int, float32, float64:
				return MaxValueMsg(maxValue)
			default:
				return MaxCharsMsg(maxValue)
			}
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case int:
				return val <= maxValue
			case float64:
				return val <= float64(maxValue)
			case float32:
				return val <= float32(maxValue)
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

// The field value must implement the comparable interface.
//
// The value of the field should be equal to at least one of the provided values.
//
// Example usage:
//
//	EntityUserTypes := [6]string{"q", "w", "e", "r", "t", "y"}
//	e := &Entity{UserType: "default", SomeOtherOptionField: 4}
//
//	fields := safe.Fields{
//		{
//			Name:  "UserType",
//			Value: e.UserType,
//			Rules: safe.Rules{safe.Required(), safe.OneOf(EntityUserTypes[:])},
//		},
//		{
//			Name:  "SomeOtherOptionField",
//			Value: e.SomeOtherOptionField,
//			Rules: safe.Rules{safe.Required(), safe.OneOf([]int{1, 2, 3})},
//		},
//	}
func OneOf[T comparable](vals []T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.OneOf",
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

// Exactly the opposite of safe.OneOf.
func NotOneOf[T comparable](vals []T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotOneOf",
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

// The field is required, just like safe.Required.
//
// However, if any of the provided vals are valid (meaning, if at least of one them have no zero value),
// then pass.
//
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name: "Email",
//			Value: user.Email,
//			Rules: safe.Rules{safe.Email(), safe.Max(128), safe.RequiredUnless(user.Username)},
//		},
//		{
//			Name: "Username",
//			Value: user.Username,
//			Rules: safe.Rules{safe.Required(), safe.Max(128), safe.Min(3)},
//		},
//	}
//
// In the example above, email is required, unless username is provided.
func RequiredUnless(vals ...any) *RuleSet {
	return &RuleSet{
		RuleName: "safe.RequiredUnless",
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

// The field must be of type time.Time, and it's value should be after the provided datetime.
func After(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.After",
		MessageFunc: func(rs *RuleSet) string {
			return IlogicalDatesMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return val.After(dt)
			}

			return false
		},
	}

}

// The field must be of type time.Time, and it's value should not be after the provided datetime.
func NotAfter(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotAfter",
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

// The field must be of type time.Time, and it's value should be before the provided datetime.
func Before(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Before",
		MessageFunc: func(rs *RuleSet) string {
			return IlogicalDatesMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return val.Before(dt)
			}

			return false
		},
	}

}

// The field must be of type time.Time, and it's value should not be before the provided datetime.
func NotBefore(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotBefore",
		MessageFunc: func(rs *RuleSet) string {
			return IlogicalDatesMsg
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return !val.Before(dt)
			}

			return false
		},
	}

}

// The field must be of type time.Time.
//
// The days range between the value of the field and the provided datetime should not be greater than maxDays.
func MaxDaysRange(dt time.Time, maxDays int) *RuleSet {
	return &RuleSet{
		RuleName: "safe.MaxDaysRange",
		MessageFunc: func(rs *RuleSet) string {
			return MaxDaysRangeMsg(maxDays)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				diffInDays := DaysDifference(dt, val)
				return diffInDays <= maxDays
			}

			return false
		},
	}

}
