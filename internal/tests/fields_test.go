package tests

import (
	"maps"
	"testing"

	"github.com/cayo-rodrigues/safe"
	"github.com/cayo-rodrigues/safe/constants/languages"
	"github.com/cayo-rodrigues/safe/messages"
)

func freshFields() safe.Fields {
	return sampleFields(newSampleUser())
}

func zeroValueFields() safe.Fields {
	return safe.Fields{
		{Name: "field_1", Value: 0, Rules: safe.Rules{safe.Required()}},
		{Name: "field_2", Value: 0, Rules: safe.Rules{safe.Required()}},
	}
}

func TestFields(t *testing.T) {
	t.Run("SetRules replaces the rules of a field", func(t *testing.T) {
		fields := freshFields()
		newRules := safe.Rules{safe.AlphaNumeric()}

		fields.SetRules("id", newRules)

		got := fields.GetField("id").Rules
		if len(got) != len(newRules) {
			t.Fatalf("Expected id rules to be replaced by %d rule(s), got %d ('%s')", len(newRules), len(got), got)
		}
		if got[0] != newRules[0] {
			t.Fatalf("Expected id rules to be '%s', got '%s'", newRules, got)
		}
	})

	t.Run("SetValue", func(t *testing.T) {
		fields := freshFields()
		expected := "a-new-id"

		fields.SetValue("id", expected)

		got := fields.GetField("id").Value
		if got != expected {
			t.Fatalf("Expected id value to be '%s', got '%v'", expected, got)
		}
	})

	t.Run("SetValue does nothing for an unknown field name", func(t *testing.T) {
		fields := freshFields()
		expected := len(fields)

		fields.SetValue("does-not-exist", "whatever")

		if got := len(fields); got != expected {
			t.Fatalf("Expected fields len to remain %d, got %d", expected, got)
		}
	})

	t.Run("SetValues only touches the named fields", func(t *testing.T) {
		fields := freshFields()
		untouched := fields.GetField("email").Value

		fields.SetValues(map[string]any{
			"id":   "another-id",
			"name": "another-name",
		})

		if got := fields.GetField("id").Value; got != "another-id" {
			t.Fatalf("Expected id value to be 'another-id', got '%v'", got)
		}
		if got := fields.GetField("name").Value; got != "another-name" {
			t.Fatalf("Expected name value to be 'another-name', got '%v'", got)
		}
		if got := fields.GetField("email").Value; got != untouched {
			t.Fatalf("Expected email value to remain '%v', got '%v'", untouched, got)
		}
	})

	t.Run("SetField creates a new field when the name does not exist", func(t *testing.T) {
		fields := freshFields()
		expectedLen := len(fields) + 1

		newField := &safe.Field{
			Value: "some value",
			Rules: safe.Rules{safe.Required()},
		}
		fields.SetField("brand_new_field", newField)

		if got := len(fields); got != expectedLen {
			t.Fatalf("Expected fields len to be %d, got %d", expectedLen, got)
		}

		got := fields.GetField("brand_new_field")
		if got == nil {
			t.Fatalf("Expected to find the newly created field, got nil")
		}
		if got.Name != "brand_new_field" {
			t.Fatalf("Expected SetField to backfill Name as 'brand_new_field', got '%s'", got.Name)
		}
		if got != newField {
			t.Fatalf("Expected the stored field to be the instance passed to SetField, got '%s'", got)
		}
	})

	t.Run("SetField replaces an existing field", func(t *testing.T) {
		fields := freshFields()
		expectedLen := len(fields)

		newField := &safe.Field{
			Name:  "id",
			Value: "replaced-id",
			Rules: safe.Rules{safe.Required()},
		}
		fields.SetField("id", newField)

		if got := len(fields); got != expectedLen {
			t.Fatalf("Expected fields len to remain %d, got %d", expectedLen, got)
		}

		got := fields.GetField("id")
		if got != newField {
			t.Fatalf("Expected the id field to be replaced by newField, got '%s'", got)
		}
		if got.Value != "replaced-id" {
			t.Fatalf("Expected id value to be 'replaced-id', got '%v'", got.Value)
		}
	})

	t.Run("SetLanguage changes the language of every error message", func(t *testing.T) {
		fields := freshFields()

		fields.SetLanguage(languages.EN_US)
		fields.SetValue("name", "")

		for _, f := range fields {
			for _, r := range f.Rules {
				if r.Language != languages.EN_US {
					t.Errorf("Expected rule '%s' of field '%s' to have language '%s', got '%s'", r.RuleName, f.Name, languages.EN_US, r.Language)
				}
			}
		}

		expected := messages.MandatoryFieldMsg(languages.EN_US)
		if got := fields.Validate()["name"]; got != expected {
			t.Fatalf("Expected name error message to be '%s', got '%s'", expected, got)
		}
	})

	t.Run("SetRuleOpts only affects the named fields", func(t *testing.T) {
		fields := zeroValueFields()

		fields.SetRuleOpts([]string{"field_1"}, safe.RuleSetOpts{AcceptNumberZero: true})

		got := fields.Validate()
		if msg, hasErr := got["field_1"]; hasErr {
			t.Errorf("Expected field_1 to accept 0 once AcceptNumberZero is set, got '%s'", msg)
		}

		expected := messages.MandatoryFieldMsg()
		if msg := got["field_2"]; msg != expected {
			t.Errorf("Expected field_2 to still reject 0 with '%s', got '%s'", expected, msg)
		}
	})

	t.Run("SetRuleOptsForAll affects every field", func(t *testing.T) {
		fields := zeroValueFields()

		if got := fields.Validate(); len(got) != len(fields) {
			t.Fatalf("Expected all %d fields to reject 0 before opts are set, got '%s'", len(fields), got)
		}

		fields.SetRuleOptsForAll(safe.RuleSetOpts{AcceptNumberZero: true})

		if got := fields.Validate(); got != nil {
			t.Fatalf("Expected all fields to accept 0 once AcceptNumberZero is set, got '%s'", got)
		}
	})

	t.Run("GetField returns nil for an unknown field name", func(t *testing.T) {
		fields := freshFields()

		if got := fields.GetField("does-not-exist"); got != nil {
			t.Fatalf("Expected nil, got '%s'", got)
		}
	})

	t.Run("Validate delegates to safe.Validate", func(t *testing.T) {
		fields := freshFields()

		if got := fields.Validate(); got != nil {
			t.Fatalf("Expected a valid user to produce no error messages, got '%s'", got)
		}

		fields.SetValue("name", "")

		got := fields.Validate()
		expected := safe.Validate(fields)

		if !maps.Equal(got, expected) {
			t.Fatalf("Expected fields.Validate() to match safe.Validate(fields) '%s', got '%s'", expected, got)
		}
		if msg := got["name"]; msg != messages.MandatoryFieldMsg() {
			t.Fatalf("Expected name error message to be '%s', got '%s'", messages.MandatoryFieldMsg(), msg)
		}
	})
}

func TestField(t *testing.T) {
	newField := func() *safe.Field {
		return &safe.Field{
			Name:  "username",
			Value: "cayo",
			Rules: safe.Rules{safe.Required(), safe.Min(3)},
		}
	}

	t.Run("SetRuleOpts changes how the rules behave", func(t *testing.T) {
		field := &safe.Field{
			Name:  "amount",
			Value: 0,
			Rules: safe.Rules{safe.Required()},
		}

		if err := field.Validate(); err == nil {
			t.Fatalf("Expected 0 to be rejected before AcceptNumberZero is set, got no error")
		}

		field.SetRuleOpts(safe.RuleSetOpts{AcceptNumberZero: true})

		if err := field.Validate(); err != nil {
			t.Fatalf("Expected 0 to be accepted once AcceptNumberZero is set, got '%s'", err)
		}
	})

	t.Run("SetLanguage changes the language of the error message", func(t *testing.T) {
		field := newField()
		field.Value = ""

		field.SetLanguage(languages.EN_US)

		for _, r := range field.Rules {
			if r.Language != languages.EN_US {
				t.Errorf("Expected rule '%s' to have language '%s', got '%s'", r.RuleName, languages.EN_US, r.Language)
			}
		}

		got := field.Validate()
		if got == nil {
			t.Fatalf("Expected an empty required value to produce an error, got nil")
		}

		expected := messages.MandatoryFieldMsg(languages.EN_US)
		if got.Error() != expected {
			t.Fatalf("Expected error message to be '%s', got '%s'", expected, got.Error())
		}
	})

	t.Run("Validate delegates to safe.ValidateField", func(t *testing.T) {
		field := newField()

		if got := field.Validate(); got != nil {
			t.Fatalf("Expected a valid field to produce no error, got '%s'", got)
		}

		field.Value = ""

		got := field.Validate()
		if got == nil {
			t.Fatalf("Expected an empty required value to produce an error, got nil")
		}

		expected := safe.ValidateField(field)
		if got.Error() != expected.Error() {
			t.Fatalf("Expected field.Validate() to match safe.ValidateField(field) '%s', got '%s'", expected, got)
		}
		if got.Error() != messages.MandatoryFieldMsg() {
			t.Fatalf("Expected error message to be '%s', got '%s'", messages.MandatoryFieldMsg(), got.Error())
		}
	})
}
