package tests

import (
	"encoding/json"
	"maps"
	"testing"

	"github.com/cayo-rodrigues/safe"
	"github.com/cayo-rodrigues/safe/messages"
)

type sampleApiError struct {
	StatusCode  int                `json:"status_code"`
	Msg         string             `json:"msg"`
	FieldErrors safe.ErrorMessages `json:"field_errors"`
}

func invalidFields() safe.Fields {
	return safe.Fields{
		{Name: "username", Value: "", Rules: safe.Rules{safe.Required()}},
		{Name: "cpf/cnpj", Value: "not a cpf", Rules: safe.Rules{safe.CpfCnpj()}},
	}
}

func TestErrorMessages(t *testing.T) {
	t.Run("JSON round trips field names and messages", func(t *testing.T) {
		errs := safe.Validate(invalidFields())
		if errs == nil {
			t.Fatalf("Expected invalid fields to produce error messages, got nil")
		}

		got := safe.ErrorMessages{}
		if err := json.Unmarshal(errs.JSON(), &got); err != nil {
			t.Fatalf("Expected JSON output to be valid json, got error '%s' for '%s'", err, errs.JSON())
		}

		if !maps.Equal(got, errs) {
			t.Fatalf("Expected unmarshalled messages to be '%s', got '%s'", errs, got)
		}

		expected := messages.MandatoryFieldMsg()
		if msg := got["username"]; msg != expected {
			t.Fatalf("Expected username message to be '%s', got '%s'", expected, msg)
		}

		expected = messages.InvalidFormatMsg()
		if msg := got["cpf/cnpj"]; msg != expected {
			t.Fatalf("Expected cpf/cnpj message to be '%s', got '%s'", expected, msg)
		}
	})

	t.Run("Error returns the JSON output as a string", func(t *testing.T) {
		errs := safe.Validate(invalidFields())

		expected := string(errs.JSON())
		if got := errs.Error(); got != expected {
			t.Fatalf("Expected Error() to be '%s', got '%s'", expected, got)
		}
	})

	t.Run("ErrorMessages survives being marshalled as part of a payload", func(t *testing.T) {
		errs := safe.Validate(invalidFields())

		payload, err := json.Marshal(sampleApiError{
			StatusCode:  400,
			Msg:         "invalid input",
			FieldErrors: errs,
		})
		if err != nil {
			t.Fatalf("Expected the payload to be marshalled, got error '%s'", err)
		}

		got := sampleApiError{}
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("Expected the payload to be valid json, got error '%s' for '%s'", err, payload)
		}

		if !maps.Equal(got.FieldErrors, errs) {
			t.Fatalf("Expected field_errors to be '%s', got '%s'", errs, got.FieldErrors)
		}
	})

	t.Run("A nil ErrorMessages is still usable", func(t *testing.T) {
		errs := safe.Validate(freshFields())
		if errs != nil {
			t.Fatalf("Expected valid fields to produce no error messages, got '%s'", errs)
		}

		expected := "null"
		if got := string(errs.JSON()); got != expected {
			t.Fatalf("Expected JSON() of a nil ErrorMessages to be '%s', got '%s'", expected, got)
		}
		if got := errs.Error(); got != expected {
			t.Fatalf("Expected Error() of a nil ErrorMessages to be '%s', got '%s'", expected, got)
		}
	})
}
