package tests

import (
	"testing"
	"unicode/utf8"

	"github.com/cayo-rodrigues/safe"
)

func TestValidationSuccess(t *testing.T) {
	user := newSampleUser()

	fields := sampleFields(user)

	errs, ok := safe.Validate(fields)

	if !ok || errs != nil {
		t.Errorf("User should be valid and have no error messages.\nValid: %v.\nError messages: %s.\nFields -> %s", ok, errs, fields)
	}

}

func TestValidationFailure(t *testing.T) {
	user := newSampleUser()

	user.Name = "pepsimaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaannn"
	user.Age = 17
	user.Address.Cep = ""
	user.Job = "pepsiman"
	user.Password = "ZkJ{[!#"
	user.CpfCnpj = "tananana tananana tananana pepsimaaaaan"

	maxNameChars := utf8.RuneCountInString(user.Name) - 1
	minAge := 18

	expectedNameErrMsg := safe.MaxCharsMsg(maxNameChars)
	expectedAgeErrMsg := "Your beard doesn't fool me!"

	fields := sampleFields(user)

	nameRules := safe.Rules{safe.Required(), safe.Max(maxNameChars)}
	ageRules := safe.Rules{safe.Required(), safe.Min(minAge).WithMessage(expectedAgeErrMsg)}

	fields.SetRules("name", nameRules).SetRules("age", ageRules)

	errs, ok := safe.Validate(fields)

	if ok || errs == nil {
		t.Errorf("User should not be valid and should have error messages.\nValid: %v.\nError Messages: %s.\nFields -> %s", ok, errs, fields)
	}

	if errs != nil {
		if msg := errs["name"]; msg != expectedNameErrMsg {
			t.Errorf("Expected name error message: \"%s\". Got: \"%s\"", expectedNameErrMsg, msg)
		}
		if msg := errs["age"]; msg != expectedAgeErrMsg {
			t.Errorf("Expected age error message: \"%s\". Got: \"%s\"", expectedAgeErrMsg, msg)
		}
		if msg := errs["address_city"]; msg != safe.MandatoryFieldMsg {
			t.Errorf("Expected address_city error message: \"%s\". Got: \"%s\"", safe.MandatoryFieldMsg, msg)
		}
		if msg := errs["address_state"]; msg != safe.MandatoryFieldMsg {
			t.Errorf("Expected address_state error message: \"%s\". Got: \"%s\"", safe.MandatoryFieldMsg, msg)
		}
		if msg := errs["job"]; msg != safe.UnacceptableValueMsg {
			t.Errorf("Expected job error message: \"%s\". Got: \"%s\"", safe.UnacceptableValueMsg, msg)
		}
		if msg := errs["password"]; msg != safe.WeakPasswordMsg {
			t.Errorf("Expected password error message: \"%s\". Got: \"%s\"", safe.WeakPasswordMsg, msg)
		}
		if msg := errs["cpf/cnpj"]; msg != safe.InvalidFormatMsg {
			t.Errorf("Expected cpf/cnpj error message: \"%s\". Got: \"%s\"", safe.InvalidFormatMsg, msg)
		}
	}
}
