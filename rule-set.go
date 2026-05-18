package safe

import (
	"strings"

	"github.com/cayo-rodrigues/safe/constants/languages"
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

// RuleSetOpts configures the behavior of a RuleSet at validation time.
//
// All fields default to false, which means rules behave in their strictest,
// most literal form unless explicitly opted into looser behavior. Opts are
// attached to a rule with WithOpts, or to multiple rules at once with
// Field.SetRuleOpts and Fields.SetRuleOptsForAll.
//
// Example usage:
//
//	safe.Email().WithOpts(&safe.RuleSetOpts{TrimWhitespace: true})
type RuleSetOpts struct {
	// AcceptNumberZero, when true, treats the numeric zero (0, 0.0) as
	// "having a value" for presence checks. Without it, safe.Required and
	// related flow rules reject zero as a missing value.
	//
	// Consumed by: safe.Required (via HasValue), safe.RequiredUnless,
	// safe.RequiredIf, safe.StopIfNoValue.
	AcceptNumberZero bool

	// TrimWhitespace, when true, makes string rules validate against the
	// leading/trailing-trimmed value. Useful for inputs that may have been
	// pasted with surrounding whitespace. The original field value is not
	// mutated — only what the rule sees during its check.
	//
	// Consumed by every string-format rule (Email, Phone, Cpf, Cnpj,
	// CpfCnpj, CEP, UUIDstr, NoWhitespace, StrongPassword, Match,
	// Min/Max in the string case, Contains and its variants, Alpha,
	// Numeric, AlphaNumeric, URL, StrictURL).
	TrimWhitespace bool

	// AllowWhitespace, when true, makes character-class rules accept
	// whitespace as a valid character (e.g. "John Doe" passes safe.Alpha).
	// A wholly-whitespace string still fails. Unlike TrimWhitespace, this
	// does not modify the value under validation — it widens the character
	// class that the rule considers valid.
	//
	// Consumed by: safe.Alpha, safe.Numeric, safe.AlphaNumeric.
	AllowWhitespace bool
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

// validateCharClass delegates to IsCharClass, threading the AllowWhitespace
// opt as the skipWhitespace argument. Pre-condition: str is non-empty (the
// caller handles the empty-string-passes convention before calling this).
func (rs *RuleSet) validateCharClass(str string, inClass func(rune) bool) bool {
	return IsCharClass(str, inClass, rs.opts().AllowWhitespace)
}

func (rs *RuleSet) String() string {
	return rs.RuleName
}
