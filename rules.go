package safe

import (
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cayo-rodrigues/safe/constants/languages"
	"github.com/cayo-rodrigues/safe/messages"
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
// An interesting feature of safe.RuleSet is its FlowFunc. It allows for a rule set to
// control the flow of validations. If the flow func returns true, then proceed with next
// validations, otherwise stop.
//
// Usualy, safe.RuleSet is not used directly.
//
// This library exposes functions that return a *safe.RuleSet. You can also make your own!
type RuleSet struct {
	RuleName     string
	FieldValue   any
	MessageFunc  func(*RuleSet) string
	ValidateFunc func(*RuleSet) bool // returns true if is valid, false otherwise
	FlowFunc     func(*RuleSet) bool // returns true if should proceed, false otherwise
	Language     languages.Language
	Opts         *RuleSetOpts
}

type RuleSetOpts struct {
	AcceptNumberZero bool
	TrimWhitespace   bool
	AllowWhitespace  bool
}

func NewRuleSet(ruleName string) *RuleSet {
	return &RuleSet{
		RuleName: ruleName,
		Opts:     &RuleSetOpts{},
	}
}

// Modifies a default message from a RuleSet, effectively letting you provide your own custom error messages.
//
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name:  "Username",
//			Value: u.Username,
//			Rules: safe.Rules{safe.Required().WithMessage("r u kidding?")},
//		},
//	}
func (rs *RuleSet) WithMessage(msg string) *RuleSet {
	rs.MessageFunc = func(rs *RuleSet) string {
		return msg
	}

	return rs
}

func (rs *RuleSet) WithOpts(opts *RuleSetOpts) *RuleSet {
	rs.Opts = opts
	return rs
}

func (rs *RuleSet) WithMessageFunc(f func(*RuleSet) string) *RuleSet {
	rs.MessageFunc = f
	return rs
}

func (rs *RuleSet) WithValidateFunc(f func(*RuleSet) bool) *RuleSet {
	rs.ValidateFunc = f
	return rs
}

func (rs *RuleSet) WithFlowFunc(f func(*RuleSet) bool) *RuleSet {
	rs.FlowFunc = f
	return rs
}

// opts returns a non-nil *RuleSetOpts. When rs.Opts is nil (rare — all
// library constructors initialize it), returns a zero-value options struct so
// callers can read fields unconditionally without a nil-check.
// The returned pointer must not be mutated when rs.Opts was nil.
func (rs *RuleSet) opts() *RuleSetOpts {
	if rs.Opts == nil {
		return &RuleSetOpts{}
	}
	return rs.Opts
}

func (rs *RuleSet) HasValue() bool {
	if rs.opts().AcceptNumberZero {
		return HasValue__SkipNumeric(rs.FieldValue)
	}
	return HasValue(rs.FieldValue)
}

// preprocessString applies opt-driven transforms to a string field value.
// Returns the (possibly trimmed) string and whether the assertion succeeded.
// Operates on a LOCAL copy only — neither rs.FieldValue nor the underlying
// Field.Value is mutated, so subsequent rules in the chain see the original.
func (rs *RuleSet) preprocessString() (string, bool) {
	str, ok := rs.FieldValue.(string)
	if !ok {
		return "", false
	}
	if rs.opts().TrimWhitespace {
		str = strings.TrimSpace(str)
	}
	return str, true
}

// validateCharClass returns true iff every rune in str is accepted by inClass,
// honoring the AllowWhitespace opt. When AllowWhitespace is set, whitespace
// runes are skipped (not matched against inClass); a wholly-whitespace string
// returns false. Pre-condition: str is non-empty (the caller handles the
// empty-string-passes convention before calling this).
func (rs *RuleSet) validateCharClass(str string, inClass func(rune) bool) bool {
	allowWS := rs.opts().AllowWhitespace
	sawClassMember := false
	for _, r := range str {
		if unicode.IsSpace(r) {
			if allowWS {
				continue
			}
			return false
		}
		if !inClass(r) {
			return false
		}
		sawClassMember = true
	}
	if allowWS && !sawClassMember {
		return false
	}
	return true
}

func isASCIIDigit(r rune) bool   { return r >= '0' && r <= '9' }
func isAlphaNumeric(r rune) bool { return unicode.IsLetter(r) || isASCIIDigit(r) }

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
//			Rules: safe.Rules{safe.Required().WithOpts(&safe.RuleSetOpts{
//				AcceptNumberZero: true,
//			})},
//		},
//		{
//			Name:  "BooleanField",
//			Value: u.BooleanField,
//			Rules: safe.Rules{safe.Required()},
//		},
//	}
//	errors := safe.Validate(fields)
//
// In the example above, username field will not be valid, but the boolean field is valid,
// because it has a value. In essence, safe.Required bypasses boolean fields.
//
// To validate boolean fields more specificaly, use safe.True and safe.False.
func Required() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Required",
		MessageFunc: func(rs *RuleSet) string {
			return messages.MandatoryFieldMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			return rs.HasValue()
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a bool with value of true
func True() *RuleSet {
	return &RuleSet{
		RuleName: "safe.True",
		MessageFunc: func(rs *RuleSet) string {
			return messages.MandatoryFieldMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			boolean, ok := rs.FieldValue.(bool)
			if !ok {
				return false
			}
			return boolean == true
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a bool with value of false
func False() *RuleSet {
	return &RuleSet{
		RuleName: "safe.False",
		MessageFunc: func(rs *RuleSet) string {
			return messages.MandatoryFieldMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			boolean, ok := rs.FieldValue.(bool)
			if !ok {
				return false
			}
			return boolean == false
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid email format.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func Email() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Email",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return EmailRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid phone format.
//
// It may or may not include symbols (like +, - and ())
// or whitespaces.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func Phone() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Phone",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return PhoneRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid cpf format.
//
// It may or may not include symbols.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func Cpf() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Cpf",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CpfRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid cnpj format.
//
// It may or may not include symbols.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func Cnpj() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Cnpj",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CnpjRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid cpf or cnpj format.
//
// It may or may not include symbols.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func CpfCnpj() *RuleSet {
	return &RuleSet{
		RuleName: "safe.CpfCnpj",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CpfRegex.MatchString(str) || CnpjRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid cep format.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func CEP() *RuleSet {
	return &RuleSet{
		RuleName: "safe.CEP",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return CepRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a strong password pattern.
//
// This means 8+ characters, with lowercase and uppercase letters, numbers and special characters.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func StrongPassword() *RuleSet {
	return &RuleSet{
		RuleName: "safe.StrongPassword",
		MessageFunc: func(rs *RuleSet) string {
			return messages.WeakPasswordMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			pwd, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if pwd == "" {
				return true
			}

			return IsStrongPassword(pwd)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with a valid format for a uuid v1, v4, v5 or v7.
//
// In case you are using a uuid package like google's, you will likely
// not need this, because you will already have a uuid validation method.
//
// Besides that, most of the time the database itself will generate the uuids.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func UUIDstr() *RuleSet {
	return &RuleSet{
		RuleName: "safe.UUIDstr",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			uuid, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if uuid == "" {
				return true
			}

			return UUIDRegex.MatchString(uuid)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string with no whitespaces.
//
// This includes characters like \n (linebreaks) and \t (tabs).
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string
// (allowing leading/trailing whitespace while still rejecting internal whitespace).
func NoWhitespace() *RuleSet {
	return &RuleSet{
		RuleName: "safe.NoWhitespaces",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return NoWhitespaceRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string containing only letters (any Unicode letter,
// including accented characters like "João").
//
// Set Opts.AllowWhitespace to true to also accept whitespace characters
// (a whitespace-only string still fails).
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
// Empty strings are considered valid; use safe.Required to enforce presence.
func Alpha() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Alpha",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return rs.validateCharClass(str, unicode.IsLetter)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string containing only digits 0-9.
//
// Set Opts.AllowWhitespace to true to also accept whitespace characters
// (a whitespace-only string still fails).
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
// Empty strings are considered valid; use safe.Required to enforce presence.
//
// Negative numbers and decimals are not valid — use safe.GreaterThan / safe.Min
// on a typed numeric value instead.
func Numeric() *RuleSet {
	return &RuleSet{
		RuleName: "safe.Numeric",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return rs.validateCharClass(str, isASCIIDigit)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string containing only letters and digits.
// Accepts any Unicode letter plus ASCII digits 0-9.
//
// Set Opts.AllowWhitespace to true to also accept whitespace characters
// (a whitespace-only string still fails).
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
// Empty strings are considered valid; use safe.Required to enforce presence.
func AlphaNumeric() *RuleSet {
	return &RuleSet{
		RuleName: "safe.AlphaNumeric",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return rs.validateCharClass(str, isAlphaNumeric)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string matching a URL format. The http/https scheme is
// optional, so bare hosts like "github.com" or "example.com/path" pass.
// Requires at least one dot in the host. Use safe.StrictURL if you want
// to require an explicit scheme.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
// Empty strings are considered valid; use safe.Required to enforce presence.
func URL() *RuleSet {
	return &RuleSet{
		RuleName: "safe.URL",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return URLRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string matching a full URL format with an explicit
// http:// or https:// scheme. Bare hosts like "github.com" fail; use safe.URL
// for the relaxed variant.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
// Empty strings are considered valid; use safe.Required to enforce presence.
func StrictURL() *RuleSet {
	return &RuleSet{
		RuleName: "safe.StrictURL",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return StrictURLRegex.MatchString(str)
		},
		Opts: &RuleSetOpts{},
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
			return messages.UniqueListMsg(rs.Language)
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
		Opts: &RuleSetOpts{},
	}
}

// The field must be a string that matches all the given regexes.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func Match(regexes ...*regexp.Regexp) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Match",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
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
		Opts: &RuleSetOpts{},
	}

}

// The field must be a slice of string, in which all strings match all the given regexes.
func MatchList(regexes ...*regexp.Regexp) *RuleSet {
	return &RuleSet{
		RuleName: "safe.MatchList",
		MessageFunc: func(rs *RuleSet) string {
			return messages.InvalidFormatMsg(rs.Language)
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
		Opts: &RuleSetOpts{},
	}

}

// The field must be an int, float64, float32 or string.
//
// In case it is a numeric value, it must not be less then minValue.
//
// As for strings, they must not have less then minValue number of characters.
// Set Opts.TrimWhitespace to true to count characters of the trimmed string.
func Min(minValue int) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Min",
		MessageFunc: func(rs *RuleSet) string {
			switch rs.FieldValue.(type) {
			case int, float32, float64:
				return messages.MinValueMsg(minValue, rs.Language)
			default:
				return messages.MinCharsMsg(minValue, rs.Language)
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
				if rs.opts().TrimWhitespace {
					val = strings.TrimSpace(val)
				}
				if val == "" {
					return true
				}
				return utf8.RuneCountInString(val) >= minValue
			}

			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// The field must be an int, float64, float32 or string.
//
// In case it is a numeric value, it must not greater then maxValue.
//
// As for strings, they must not have more then maxValue number of characters.
// Set Opts.TrimWhitespace to true to count characters of the trimmed string.
func Max(maxValue int) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Max",
		MessageFunc: func(rs *RuleSet) string {
			switch rs.FieldValue.(type) {
			case int, float32, float64:
				return messages.MaxValueMsg(maxValue, rs.Language)
			default:
				return messages.MaxCharsMsg(maxValue, rs.Language)
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
				if rs.opts().TrimWhitespace {
					val = strings.TrimSpace(val)
				}
				if val == "" {
					return true
				}
				return utf8.RuneCountInString(val) <= maxValue
			}

			return false
		},
		Opts: &RuleSetOpts{},
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
			return messages.UnacceptableValueMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			for _, val := range vals {
				if val == rs.FieldValue {
					return true
				}
			}
			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// Exactly the opposite of safe.OneOf.
func NotOneOf[T comparable](vals []T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotOneOf",
		MessageFunc: func(rs *RuleSet) string {
			return messages.UnacceptableValueMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			for _, val := range vals {
				if val == rs.FieldValue {
					return false
				}
			}
			return true
		},
		Opts: &RuleSetOpts{},
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
			return messages.MandatoryFieldMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			if rs.HasValue() {
				return true
			}
			if rs.opts().AcceptNumberZero {
				return SomeFunc(HasValue__SkipNumeric, vals...)
			}
			return Some(vals...)
		},
		Opts: &RuleSetOpts{},
	}

}

// The field is not required by default.
//
// However, if any of the provided vals are valid (meaning, if at least of one them have no zero value),
// then the field becomes required.
//
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name: "Email",
//			Value: user.Email,
//			Rules: safe.Rules{safe.Email(), safe.Max(128), safe.RequiredIf(user.Username)},
//		},
//		{
//			Name: "Username",
//			Value: user.Username,
//			Rules: safe.Rules{safe.Max(128), safe.Min(3)},
//		},
//	}
//
// In the example above, email is required only when username is provided.
func RequiredIf(vals ...any) *RuleSet {
	return &RuleSet{
		RuleName: "safe.RequiredIf",
		MessageFunc: func(rs *RuleSet) string {
			return messages.MandatoryFieldMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			if rs.HasValue() {
				return true
			}
			if rs.opts().AcceptNumberZero {
				return NoneFunc(HasValue__SkipNumeric, vals...)
			}
			return None(vals...)
		},
		Opts: &RuleSetOpts{},
	}

}

// The field must be of type time.Time, and it's value should be after the provided datetime.
func After(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.After",
		MessageFunc: func(rs *RuleSet) string {
			return messages.IlogicalDatesMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return val.After(dt)
			}

			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// The field must be of type time.Time, and it's value should not be after the provided datetime.
func NotAfter(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotAfter",
		MessageFunc: func(rs *RuleSet) string {
			return messages.IlogicalDatesMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return !val.After(dt)
			}

			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// The field must be of type time.Time, and it's value should be before the provided datetime.
func Before(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Before",
		MessageFunc: func(rs *RuleSet) string {
			return messages.IlogicalDatesMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return val.Before(dt)
			}

			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// The field must be of type time.Time, and it's value should not be before the provided datetime.
func NotBefore(dt time.Time) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotBefore",
		MessageFunc: func(rs *RuleSet) string {
			return messages.IlogicalDatesMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				return !val.Before(dt)
			}

			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// The field must be of type time.Time.
//
// The days range between the value of the field and the provided datetime should not be greater than maxDays.
func MaxDaysRange(dt time.Time, maxDays int) *RuleSet {
	return &RuleSet{
		RuleName: "safe.MaxDaysRange",
		MessageFunc: func(rs *RuleSet) string {
			return messages.MaxDaysRangeMsg(maxDays, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			switch val := rs.FieldValue.(type) {
			case time.Time:
				diffInDays := DifferenceInDays(dt, val)
				return diffInDays <= maxDays
			}

			return false
		},
		Opts: &RuleSetOpts{},
	}

}

// The field value must implement the comparable interface.
//
// The value of the field should be equal to the provided value.
//
// This rule behaves exactly like safe.OneOf, but with only one value to compare
func EqualTo[T comparable](value T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.EqualTo",
		MessageFunc: func(rs *RuleSet) string {
			return messages.UnacceptableValueMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			return rs.FieldValue == value
		},
		Opts: &RuleSetOpts{},
	}
}

// Exactly the opposite of safe.EqualTo.
func NotEqualTo[T comparable](value T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotEqualTo",
		MessageFunc: func(rs *RuleSet) string {
			return messages.UnacceptableValueMsg(rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			return rs.FieldValue != value
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be like T, either an int, a float64 or a float32
//
// The value of the field must be greater than n
func GreaterThan[T int | float64 | float32](n T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.GreaterThan",
		MessageFunc: func(rs *RuleSet) string {
			return messages.GreaterThanMsg(n, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			fieldVal, ok := AnyToFloat64(rs.FieldValue)
			if !ok {
				return false
			}

			return fieldVal > float64(n)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be like T, either an int, a float64 or a float32
//
// The value of the field must be greater than or equal to n
func GreaterThanOrEqualTo[T int | float64 | float32](n T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.GreaterThanOrEqualTo",
		MessageFunc: func(rs *RuleSet) string {
			return messages.GreaterThanOrEqualToMsg(n, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			fieldVal, ok := AnyToFloat64(rs.FieldValue)
			if !ok {
				return false
			}

			return fieldVal >= float64(n)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be like T, either an int, a float64 or a float32
//
// The value of the field must be less than n
func LessThan[T int | float64 | float32](n T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.LessThan",
		MessageFunc: func(rs *RuleSet) string {
			return messages.LessThanMsg(n, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			fieldVal, ok := AnyToFloat64(rs.FieldValue)
			if !ok {
				return false
			}

			return fieldVal < float64(n)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be like T, either an int, a float64 or a float32
//
// The value of the field must be greater than or equal to n
func LessThanOrEqualTo[T int | float64 | float32](n T) *RuleSet {
	return &RuleSet{
		RuleName: "safe.LessThanOrEqualTo",
		MessageFunc: func(rs *RuleSet) string {
			return messages.LessThanOrEqualToMsg(n, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			fieldVal, ok := AnyToFloat64(rs.FieldValue)
			if !ok {
				return false
			}

			return fieldVal <= float64(n)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be of type string
//
// The value of the field must contain substr.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func Contains(substr string) *RuleSet {
	return &RuleSet{
		RuleName: "safe.Contains",
		MessageFunc: func(rs *RuleSet) string {
			return messages.ContainsMsg(substr, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return strings.Contains(str, substr)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be of type string
//
// The value of the field must not contain substr.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func NotContains(substr string) *RuleSet {
	return &RuleSet{
		RuleName: "safe.NotContains",
		MessageFunc: func(rs *RuleSet) string {
			return messages.NotContainsMsg(substr, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			return !strings.Contains(str, substr)
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be of type string
//
// The value of the field must contain all substrs.
//
// Note that this is different from strings.ContainsAny, because
// we compare substrings, not unicode code points.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func ContainsAll(substrs ...string) *RuleSet {
	return &RuleSet{
		RuleName: "safe.ContainsAll",
		MessageFunc: func(rs *RuleSet) string {
			return messages.ContainsAllMsg(substrs, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			for _, substr := range substrs {
				if !strings.Contains(str, substr) {
					return false
				}
			}
			return true
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be of type string
//
// The value of the field must contain at least one of substrs.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func ContainsSome(substrs ...string) *RuleSet {
	return &RuleSet{
		RuleName: "safe.ContainsSome",
		MessageFunc: func(rs *RuleSet) string {
			return messages.ContainsSomeMsg(substrs, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			for _, substr := range substrs {
				if strings.Contains(str, substr) {
					return true
				}
			}
			return false
		},
		Opts: &RuleSetOpts{},
	}
}

// The field value must be of type string
//
// None of the substrs should be found in the field value.
//
// Set Opts.TrimWhitespace to true to validate against the trimmed string.
func ContainsNone(substrs ...string) *RuleSet {
	return &RuleSet{
		RuleName: "safe.ContainsNone",
		MessageFunc: func(rs *RuleSet) string {
			return messages.ContainsNoneMsg(substrs, rs.Language)
		},
		ValidateFunc: func(rs *RuleSet) bool {
			str, ok := rs.preprocessString()
			if !ok {
				return false
			}

			if str == "" {
				return true
			}

			for _, substr := range substrs {
				if strings.Contains(str, substr) {
					return false
				}
			}
			return true
		},
		Opts: &RuleSetOpts{},
	}
}

// A flow rule.
//
// Stop validation for the field if the field has no value.
//
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name:  "limit",
//			Value: filters.Limit,
//			Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(10), safe.RequiredIf(filters.Offset)},
//		},
//		{
//			Name:  "offset",
//			Value: filters.Offset,
//			Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(0), safe.RequiredIf(filters.Limit)},
//		},
//		{
//			Name:  "order_by",
//			Value: filters.OrderBy,
//			Rules: safe.Rules{safe.OneOf([]string{"created_at"})},
//		},
//		{
//			Name:  "search",
//			Value: filters.Search,
//			Rules: safe.Rules{safe.Max(128)},
//		},
//	}
//
//	fields.SetRuleOptsForAll(&safe.RuleSetOpts{
//		AcceptNumberZero: true,
//	})
//
// In the example above, filters.Limit and filters.Offset will be validated only when they have a value.
// Otherwise, validation is skipped.
func StopIfNoValue() *RuleSet {
	return &RuleSet{
		RuleName: "safe.StopIfNoValue",
		FlowFunc: func(rs *RuleSet) bool {
			return rs.HasValue()
		},
		Opts: &RuleSetOpts{},
	}
}

// A flow rule.
//
// Stop validation for the field if the provided condition is met.
func StopIf(cond bool) *RuleSet {
	return &RuleSet{
		RuleName: "safe.StopIf",
		FlowFunc: func(rs *RuleSet) bool {
			return !cond
		},
		Opts: &RuleSetOpts{},
	}
}

// A flow rule.
//
// Stop validation for the field if the provided func returns true.
func StopIfFunc(f func(fieldValue any) bool) *RuleSet {
	return &RuleSet{
		RuleName: "safe.StopIfFunc",
		FlowFunc: func(rs *RuleSet) bool {
			return !f(rs.FieldValue)
		},
		Opts: &RuleSetOpts{},
	}
}
