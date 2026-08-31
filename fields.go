package safe

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cayo-rodrigues/safe/constants/languages"
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

// Set values for multiple fields. This will overwrite the existing values in the fields.
//
// The key is the field.Name and the value is the new value to be assigned.
// Example usage:
//
//	fields := safe.Fields{
//		{
//			Name: "field_1",
//			Value: "field_1_value",
//			Rules: safe.Rules{...},
//		},
//		{
//			Name: "field_2",
//			Value: "field_2_value",
//			Rules: safe.Rules{...},
//		},
//		{
//			Name: "field_3",
//			Value: "field_3_value",
//			Rules: safe.Rules{...},
//		},
//	}
//	fields.SetValues(map[string]any{
//		"field_1":    "another_value_for_field_1",
//		"field_2":    "another_value_for_field_2",
//		"field_3":    "another_value_for_field_3",
//	})
func (fields *Fields) SetValues(values map[string]any) *Fields {
	for _, f := range *fields {
		value, ok := values[f.Name]
		if !ok {
			continue
		}
		f.Value = value
	}

	return fields
}

// Create a new field or update an existing field.
func (fields *Fields) SetField(fieldName string, newField *Field) *Fields {
	for i, f := range *fields {
		if f.Name == fieldName {
			(*fields)[i] = newField
			return fields
		}
	}

	if newField.Name == "" {
		newField.Name = fieldName
	}

	*fields = append(*fields, newField)

	return fields
}

// Sets the language for all field rules
//
// If no language is set, it defaults to messages.DefaultLang
func (fields *Fields) SetLanguage(lang languages.Language) *Fields {
	for _, f := range *fields {
		f.SetLanguage(lang)
	}

	return fields
}

// Sets rule set options to the fields matching fieldNames
func (fields *Fields) SetRuleOpts(fieldNames []string, opts RuleSetOpts) *Fields {
	for _, f := range *fields {
		if slices.Contains(fieldNames, f.Name) {
			f.SetRuleOpts(opts)
		}
	}

	return fields
}

// Sets rule set options to all fields
func (fields *Fields) SetRuleOptsForAll(opts RuleSetOpts) *Fields {
	for _, f := range *fields {
		f.SetRuleOpts(opts)
	}

	return fields
}

// Retrieves a field by name. Returns nil if not found.
func (fields *Fields) GetField(fieldName string) *Field {
	for _, f := range *fields {
		if f.Name == fieldName {
			return f
		}
	}

	return nil
}

// Just an alternative way of validating fields. You can either:
//
//	errs := safe.Validate(fields)
//
//	// OR
//
//	errs := fields.Validate()
func (fields Fields) Validate() ErrorMessages {
	return Validate(fields)
}

func (fields *Fields) String() string {
	builder := strings.Builder{}

	builder.WriteString("Fields {\n")

	for _, f := range *fields {
		builder.WriteString("\t")
		builder.WriteString(f.String())
		builder.WriteString("\n")
	}

	builder.WriteString("}")
	return builder.String()
}

// An individual Field to be validated.
//
// It is highly advisable to use safe.Fields instead, since safe.Validate expects safe.Fields as argument.
type Field struct {
	// Name is used as a key in the ErrorMessages map when the field is not valid
	Name  string
	Value any
	Rules Rules
}

// Set rule opts for all rules in the field.
func (f *Field) SetRuleOpts(opts RuleSetOpts) *Field {
	for _, r := range f.Rules {
		r.Opts = opts
	}
	return f
}

// Set language for all rules in the field.
func (f *Field) SetLanguage(lang languages.Language) *Field {
	for _, r := range f.Rules {
		r.Language = lang
	}
	return f
}

// Just an alternative way of validating a field. You can either:
//
//	err := safe.ValidateField(field)
//
//	// OR
//
//	err := field.Validate()
func (f *Field) Validate() error {
	return ValidateField(f)
}

func (f *Field) String() string {
	return fmt.Sprintf("{ Name: %s, Value: %v, Rules: %s }", f.Name, f.Value, f.Rules)
}
