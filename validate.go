package safe

import (
	"fmt"
	"strings"
)

// A slice of fields to be validated.
// Each Field has a name, a value and a set of rules.
//
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name: "Email",
//			Value: user.Email,
//			Rules: safe.Rules{safe.Requiredi(), safe.Email(), safe.Max(128)},
//		},
//		{
//			Name: "Password",
//			Value: user.Password,
//			Rules: safe.Rules{safe.Required(), safe.Max(128), safe.StrongPassword()},
//		},
//	}
type Fields []*Field

// Set rules for a specific field. This will overwrite the existing rules in the field.
func (fields *Fields) SetRules(fieldName string, rules Rules) *Fields {
	for _, f := range *fields {
		if f.Name == fieldName {
			f.Rules = rules
			return fields
		}
	}

	return fields
}

// Set a value for a specific field. This will overwrite the existing value in the field.
func (fields *Fields) SetValue(fieldName string, value any) *Fields {
	for _, f := range *fields {
		if f.Name == fieldName {
			f.Value = value
			return fields
		}
	}

	return fields
}

// Create a new field or update an existing field.
func (fields *Fields) SetField(fieldName string, newField *Field) *Fields {
	for _, f := range *fields {
		if f.Name == fieldName {
			f = newField
			return fields
		}
	}

	*fields = append(*fields, newField)

	return fields
}

// An individual Field to be validated.
//
// It is highly advisable to use safe.Fields instead, since safe.Validate expects safe.Fields as argument.
type Field struct {
	// This is the name used as a key in the ErrorMessages map when the field is not valid
	Name  string
	Value any
	Rules Rules
}

func (f *Field) String() string {
	return fmt.Sprintf("{ Name: %s, Value: %v, Rules: %s }", f.Name, f.Value, f.Rules)
}

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

// safe.Validate returns (safe.ErrorMessages, bool).
//
// safe.ErrorMessages is a map of field names, each associated with a message.
//
// Example:
//
//	fields := safe.Fields{
//		{...}
//	}
//	errors, ok := Validate(fields)
//
//	if !ok {
//		fmt.Println("why is username not valid?", errors["Username"])
//		fmt.Println("why is email not valid?", errors["Email"])
//	}
type ErrorMessages map[string]string

// Expects Fields, which is just a []*Field. Each Field has a slice of Rules.
// All of them are evalueted sequentially.
//
// When a Field is not valid, no more validations are performed for that specific field,
// so we proceed to the next one.
//
// Validate returns two values:
//
// 1) ErrorMessages, a map in which the keys correspond
// to the Field.Name property, and the values are string error messages according to the broken rule.
//
// 2) A bool, indicating if all fields are valid or not. In case this is true, ErrorMessages is nil.
//
// Example usage:
//
//	fields := safe.Fields{
//		{...}
//	}
//	errors, ok := Validate(fields)
//
//	fmt.Println("are all fields valid?", ok)
//	fmt.Println("is there any error message?", errors)
func Validate(fields Fields) (ErrorMessages, bool) {
	var messages ErrorMessages

	for _, field := range fields {
		for _, rs := range field.Rules {
			rs.FieldValue = field.Value
			isValid := rs.ValidateFunc(rs)
			if !isValid {
				if messages == nil {
					messages = make(ErrorMessages)
				}
				msg := rs.MessageFunc(rs)
				messages[field.Name] = msg
				break // stop runing validate funcs after first fail
			}
		}
	}

	return messages, len(messages) == 0
}
