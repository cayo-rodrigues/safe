package tests

import (
	"testing"
	"unicode/utf8"

	"github.com/cayo-rodrigues/safe"
	"github.com/cayo-rodrigues/safe/messages"
)

func TestValidationSuccess(t *testing.T) {
	user := newSampleUser()

	fields := sampleFields(user)

	errs := safe.Validate(fields)

	if errs != nil {
		t.Errorf("User should be valid and have no error messages.\nError messages: %s.\nFields -> %s", errs, fields)
	}

}

func TestValidationFailure(t *testing.T) {
	user := newSampleUser()

	user.Name = "pepsimaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaannn"
	user.Age = 17
	user.sampleAddress.Cep = ""
	user.Job = "pepsiman"
	user.Password = "ZkJ{[!#"
	user.CpfCnpj = "tananana tananana tananana pepsimaaaaan"

	maxNameChars := utf8.RuneCountInString(user.Name) - 1
	minAge := 18

	expectedNameErrMsg := messages.MaxCharsMsg(maxNameChars)
	expectedAgeErrMsg := "Your beard doesn't fool me!"

	fields := sampleFields(user)

	nameRules := safe.Rules{safe.Required(), safe.Max(maxNameChars)}
	ageRules := safe.Rules{safe.Required(), safe.Min(minAge).WithMessage(expectedAgeErrMsg)}

	fields.SetRules("name", nameRules).SetRules("age", ageRules)

	errs := safe.Validate(fields)

	if errs == nil {
		t.Errorf("User should not be valid and should have error messages.\nError Messages: %s.\nFields -> %s", errs, fields)
	}

	if msg := errs["name"]; msg != expectedNameErrMsg {
		t.Errorf("Expected name error message: \"%s\". Got: \"%s\"", expectedNameErrMsg, msg)
	}
	if msg := errs["age"]; msg != expectedAgeErrMsg {
		t.Errorf("Expected age error message: \"%s\". Got: \"%s\"", expectedAgeErrMsg, msg)
	}
	if msg := errs["address_city"]; msg != messages.MandatoryFieldMsg() {
		t.Errorf("Expected address_city error message: \"%s\". Got: \"%s\"", messages.MandatoryFieldMsg(), msg)
	}
	if msg := errs["address_state"]; msg != messages.MandatoryFieldMsg() {
		t.Errorf("Expected address_state error message: \"%s\". Got: \"%s\"", messages.MandatoryFieldMsg(), msg)
	}
	if msg := errs["job"]; msg != messages.UnacceptableValueMsg() {
		t.Errorf("Expected job error message: \"%s\". Got: \"%s\"", messages.UnacceptableValueMsg(), msg)
	}
	if msg := errs["password"]; msg != messages.WeakPasswordMsg() {
		t.Errorf("Expected password error message: \"%s\". Got: \"%s\"", messages.WeakPasswordMsg(), msg)
	}
	if msg := errs["cpf/cnpj"]; msg != messages.InvalidFormatMsg() {
		t.Errorf("Expected cpf/cnpj error message: \"%s\". Got: \"%s\"", messages.InvalidFormatMsg(), msg)
	}
}
