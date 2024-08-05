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
		{Val: "", ExpectedErrMsg: safe.MandatoryFieldMsg},
		{Val: 0, ExpectedErrMsg: safe.MandatoryFieldMsg},
		{Val: nil, ExpectedErrMsg: safe.MandatoryFieldMsg},
	}
	okValues := []any{"a", -1}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestEmailRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "email",
		Rules: safe.Rules(safe.Email),
	}

	invalidValues := []*InvalidValue{
		{Val: " ", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "qqq", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "qqq@", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "qqq@aaa", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "qqq@aaa.", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "qqq@aaa. zzz", ExpectedErrMsg: safe.InvalidFormatMsg},
	}
	okValues := []any{"qqq@aaa.zzz"}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestPhoneRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "phone",
		Rules: safe.Rules(safe.Phone),
	}

	invalidValues := []*InvalidValue{
		{Val: " ", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "123", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "999445697", ExpectedErrMsg: safe.InvalidFormatMsg},
	}
	okValues := []any{
		"(35) 99944-5697",
		"(35)99944-5697",
		"35999445697",
		"5535999445697",
		"+5535999445697",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCpfRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cpf",
		Rules: safe.Rules(safe.Cpf),
	}

	invalidValues := []*InvalidValue{
		{Val: " ", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "123", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "139503176", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "139.503.176.27", ExpectedErrMsg: safe.InvalidFormatMsg},
	}
	okValues := []any{
		"13950317627",
		"139.503.176-27",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCnpjRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cnpj",
		Rules: safe.Rules(safe.Cnpj),
	}

	invalidValues := []*InvalidValue{
		{Val: " ", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "123", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "445040440001", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "44.504.044/0001-aa", ExpectedErrMsg: safe.InvalidFormatMsg},
	}
	okValues := []any{
		"44.504.044/0001-24",
		"44504044000124",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCpfCnpjRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cpf/cnpj",
		Rules: safe.Rules(safe.CpfCnpj),
	}

	invalidValues := []*InvalidValue{
		{Val: " ", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "123", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "139503176", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "139.503.176.27", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "44504044000127272", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "445040440001aa", ExpectedErrMsg: safe.InvalidFormatMsg},
		{Val: "44.504.044/0001-aa", ExpectedErrMsg: safe.InvalidFormatMsg},
	}
	okValues := []any{
		"44.504.044/0001-24",
		"44504044000124",
		"13950317627",
		"139.503.176-27",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
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
