package tests

import (
	"testing"

	"github.com/cayo-rodrigues/safe"
)

func TestRequiredRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "name",
		Rules: safe.Rules(safe.Required),
	}

	invalidValues := []*InvalidValue{
		{Val: ""},
		{Val: 0},
		{Val: nil},
	}
	okValues := []any{"a", -1}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MandatoryFieldMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestEmailRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "email",
		Rules: safe.Rules(safe.Email),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "qqq"},
		{Val: "qqq@"},
		{Val: "qqq@aaa"},
		{Val: "qqq@aaa."},
		{Val: "qqq@aaa. zzz"},
	}
	okValues := []any{"qqq@aaa.zzz"}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestPhoneRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "phone",
		Rules: safe.Rules(safe.Phone),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "999445697"},
	}
	okValues := []any{
		"(35) 99944-5697",
		"(35)99944-5697",
		"35999445697",
		"5535999445697",
		"+5535999445697",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCpfRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cpf",
		Rules: safe.Rules(safe.Cpf),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "139503176"},
		{Val: "139.503.176.27"},
	}
	okValues := []any{
		"13950317627",
		"139.503.176-27",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCnpjRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cnpj",
		Rules: safe.Rules(safe.Cnpj),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "445040440001"},
		{Val: "44.504.044/0001-aa"},
	}
	okValues := []any{
		"44.504.044/0001-24",
		"44504044000124",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCpfCnpjRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cpf/cnpj",
		Rules: safe.Rules(safe.CpfCnpj),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "139503176"},
		{Val: "139.503.176.27"},
		{Val: "44504044000127272"},
		{Val: "445040440001aa"},
		{Val: "44.504.044/0001-aa"},
	}
	okValues := []any{
		"44.504.044/0001-24",
		"44504044000124",
		"13950317627",
		"139.503.176-27",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCEPRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cep",
		Rules: safe.Rules(safe.CEP),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "3661000"},
		{Val: "3750800"},
		{Val: "37508 000"},
	}
	okValues := []any{
		"36610000",
		"37508000",
		"36610-000",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestStrongPasswordRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "strong_password",
		Rules: safe.Rules(safe.StrongPassword),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "aaa"},
		{Val: "AAA"},
		{Val: "1q2w3e"},
		{Val: "password"},
		{Val: "AAAqqq123"},
		{Val: "qAz QwE 1Z2b9j"},
		{Val: "$3nh4fort3_"},
		{Val: "$3NH4FORT3_"},
		{Val: "$_!@%&*"},
		{Val: "$3nH4!!"},
	}
	okValues := []any{
		"$s3NH@!X",
		"$S3nh4Mu1iT0__F)rt3!",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.WeakPasswordMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestWithMessage(t *testing.T) {
	customErrMsg := "custom err msg"
	fieldData := &safe.Field{
		Name:  "email",
		Rules: safe.Rules(safe.Email().WithMessage(customErrMsg)),
	}

	invalidValues := []*InvalidValue{{Val: 0, ExpectedErrMsg: customErrMsg}}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
}
