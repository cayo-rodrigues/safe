package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/cayo-rodrigues/safe"
)

func TestRequiredRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "name",
		Rules: safe.Rules{safe.Required()},
	}

	invalidValues := []*invalidValue{
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
		Rules: safe.Rules{safe.Email()},
	}

	invalidValues := []*invalidValue{
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
		Rules: safe.Rules{safe.Phone()},
	}

	invalidValues := []*invalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "999445678"},
	}
	okValues := []any{
		"(35) 99944-5678",
		"(35)99944-5678",
		"35999445678",
		"5535999445678",
		"+5535999445678",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCpfRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cpf",
		Rules: safe.Rules{safe.Cpf()},
	}

	invalidValues := []*invalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "9004912401"},
		{Val: "308.305.800.42"},
		{Val: "393z546.320-09"},
	}
	okValues := []any{
		"11421499002",
		"393.546.320-09",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCnpjRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cnpj",
		Rules: safe.Rules{safe.Cnpj()},
	}

	invalidValues := []*invalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "575067450001"},
		{Val: "74.082.201/0001-aa"},
		{Val: "74.082.201b0001-86"},
	}
	okValues := []any{
		"45.769.852/0001-86",
		"11789602000196",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCpfCnpjRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cpf/cnpj",
		Rules: safe.Rules{safe.CpfCnpj()},
	}

	invalidValues := []*invalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "3589256907"},
		{Val: "073.27.370-96"},
		{Val: "44504044000127272"},
		{Val: "543368000001aa"},
		{Val: "43.549a814/0001-92"},
	}
	okValues := []any{
		"99.379.672/0001-17",
		"68840265000131",
		"90007645058",
		"738.691.910-74",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestCEPRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "cep",
		Rules: safe.Rules{safe.CEP()},
	}

	invalidValues := []*invalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "5432042"},
		{Val: "8908270"},
		{Val: "52120 330"},
	}
	okValues := []any{
		"77001286",
		"77414752",
		"49001-084",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestStrongPasswordRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "strong_password",
		Rules: safe.Rules{safe.StrongPassword()},
	}

	invalidValues := []*invalidValue{
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

func TestUUIDstrRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "uuid str",
		Rules: safe.Rules{safe.UUIDstr()},
	}

	invalidValues := []*invalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "aaa"},
		{Val: 0},
		{Val: "z52a3e80-9866-11eb-a8b3-0242ac130003"}, // look like v1
		{Val: "g6c3f6e4-5e6a-4f84-89fa-b1231e8bb02b"}, // look like v4
		{Val: "9b4e79a8-0a8d-5c11-83bc-04d2e569e60g"}, // look like v5
		{Val: "018a3345-6bdf-7e47-8080-060d2f507b6z"}, // look like v7
	}
	okValues := []any{
		"a52a3e80-9866-11eb-a8b3-0242ac130003", // v1
		"d6c3f6e4-5e6a-4f84-89fa-b1231e8bb02b", // v4
		"9b4e79a8-0a8d-5c11-83bc-04d2e569e60b", // v5
		"018a3345-6bdf-7e47-8080-060d2f507b6e", // v7
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestUniqueListRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "unique list",
		Rules: safe.Rules{safe.UniqueList[any]()},
	}

	invalidValues := []*invalidValue{
		{Val: []any{"aaa", "b", "aaa"}},
		{Val: []any{1, 2, 3, 4, 4}},
		{Val: []any{1, 2.5, 3.14, 3.14}},
		{Val: []any{"1", 1, "one", 1}},
	}
	okValues := []any{
		[]any{"$s3NH@!X"},
		[]any{"$s3NH@!X", "unique string", "another unique string"},
		[]any{1, 2, 3},
		[]any{1, 2, 3.333},
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.UniqueListMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestMatchRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "match",
		Rules: safe.Rules{safe.Match(safe.WhateverRegex)},
	}

	invalidValues := []*invalidValue{}
	okValues := []any{"literaly anything"}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)

	fieldData.Rules = safe.Rules{safe.Match(safe.AddressNumberRegex)}

	invalidValues = []*invalidValue{
		{Val: "abc"},
		{Val: "1 1"},
		{Val: "321 Fundos"},
	}
	okValues = []any{
		"231",
		"s/n",
		"S/N",
		"s/N",
		"S/n",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestMatchListRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "match list",
		Rules: safe.Rules{safe.MatchList(safe.WhateverRegex)},
	}

	invalidValues := []*invalidValue{}
	okValues := []any{
		[]string{"literaly anything", "whatever"},
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)

	fieldData.Rules = safe.Rules{safe.MatchList(safe.AddressNumberRegex)}

	invalidValues = []*invalidValue{
		{Val: []string{"abc", "1 1", "321 Fundos"}},
	}
	okValues = []any{
		[]string{"231", "s/n", "S/N", "s/N", "S/n"},
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestMinRule(t *testing.T) {
	minValue := 5

	fieldData := &safe.Field{
		Name:  "min",
		Rules: safe.Rules{safe.Min(minValue)},
	}

	invalidValues := []*invalidValue{
		{Val: 4},
		{Val: 0},
		{Val: -5},
		{Val: -6},
		{Val: 4.9999},
	}
	okValues := []any{5, 6}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MinValueMsg(minValue))
	testFieldWithOkValues(fieldData, okValues, t)

	invalidValues = []*invalidValue{
		{Val: "1234"},
		{Val: "1   "},
		{Val: " "},
		{Val: "abcq"},
	}
	okValues = []any{"pineapple", "apple", "abcdef"}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MinCharsMsg(minValue))
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestMaxRule(t *testing.T) {
	maxValue := 1

	fieldData := &safe.Field{
		Name:  "max",
		Rules: safe.Rules{safe.Max(maxValue)},
	}

	invalidValues := []*invalidValue{
		{Val: 1.000001},
		{Val: 1.1},
		{Val: 100},
	}
	okValues := []any{0, 0.5, 0.999, -1, -100}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MaxValueMsg(maxValue))
	testFieldWithOkValues(fieldData, okValues, t)

	invalidValues = []*invalidValue{
		{Val: "1234"},
		{Val: "1   "},
		{Val: "  "},
		{Val: "ab"},
	}
	okValues = []any{"p", "a", "1", "", " "}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MaxCharsMsg(maxValue))
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestOneOfRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "one of",
		Rules: safe.Rules{safe.OneOf([]any{"1", "2", "abc", 123, 99.9, "abc"})},
	}

	invalidValues := []*invalidValue{
		{Val: "1.000001"},
		{Val: 123.00001},
		{Val: 100},
		{Val: 99.99},
		{Val: "1 "},
		{Val: "ab"},
		{Val: " abc"},
		{Val: 99.8},
	}
	okValues := []any{"1", "abc", 99.9, 123}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.UnacceptableValueMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestNotOneOfRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "not one of",
		Rules: safe.Rules{safe.NotOneOf([]any{"1", "2", "abc", 123, 99.9, "abc"})},
	}

	invalidValues := []*invalidValue{
		{Val: "1"},
		{Val: "abc"},
		{Val: 99.9},
		{Val: 123},
	}
	okValues := []any{"1.000001", 123.00001, 100, 99.99, "1 ", "ab", " abc", 99.8}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.UnacceptableValueMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestRequiredUnlessRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "required unless",
		Rules: safe.Rules{safe.RequiredUnless(nil)},
	}

	invalidValues := []*invalidValue{
		{Val: ""},
		{Val: 0},
		{Val: 0.000},
		{Val: nil},
		{Val: false},
		{Val: time.Time{}},
		{Val: struct{}{}},
	}
	okValues := []any{"anything non-zero value", 1, true, time.Now()}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MandatoryFieldMsg)
	testFieldWithOkValues(fieldData, okValues, t)

	fieldData.Rules = safe.Rules{safe.RequiredUnless("", nil, 0, struct{}{}, 0.01)}

	okValues = []any{"", 0, " ", nil, 1000, "anything", time.Now(), time.Time{}}

	testFieldWithOkValues(fieldData, okValues, t)
}

func TestAfterRule(t *testing.T) {
	now := time.Now()

	fieldData := &safe.Field{
		Name:  "after",
		Rules: safe.Rules{safe.After(now)},
	}

	invalidValues := []*invalidValue{
		{Val: now},
		{Val: now.Add(-time.Hour)},
		{Val: now.Add(-time.Minute)},
		{Val: now.Add(-time.Second)},
		{Val: now.Add(-time.Millisecond)},
		{Val: now.Add(-time.Microsecond)},
	}
	okValues := []any{
		now.Add(time.Hour),
		now.Add(time.Minute),
		now.Add(time.Second),
		now.Add(time.Millisecond),
		now.Add(time.Microsecond),
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.IlogicalDatesMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestNotAfterRule(t *testing.T) {
	now := time.Now()

	fieldData := &safe.Field{
		Name:  "not after",
		Rules: safe.Rules{safe.NotAfter(now)},
	}

	invalidValues := []*invalidValue{
		{Val: now.Add(time.Hour)},
		{Val: now.Add(time.Minute)},
		{Val: now.Add(time.Second)},
		{Val: now.Add(time.Millisecond)},
		{Val: now.Add(time.Microsecond)},
	}
	okValues := []any{
		now,
		now.Add(-time.Hour),
		now.Add(-time.Minute),
		now.Add(-time.Second),
		now.Add(-time.Millisecond),
		now.Add(-time.Microsecond),
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.IlogicalDatesMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestBeforeRule(t *testing.T) {
	now := time.Now()

	fieldData := &safe.Field{
		Name:  "before",
		Rules: safe.Rules{safe.Before(now)},
	}

	invalidValues := []*invalidValue{
		{Val: now},
		{Val: now.Add(time.Hour)},
		{Val: now.Add(time.Minute)},
		{Val: now.Add(time.Second)},
		{Val: now.Add(time.Millisecond)},
		{Val: now.Add(time.Microsecond)},
	}
	okValues := []any{
		now.Add(-time.Hour),
		now.Add(-time.Minute),
		now.Add(-time.Second),
		now.Add(-time.Millisecond),
		now.Add(-time.Microsecond),
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.IlogicalDatesMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestNotBeforeRule(t *testing.T) {
	now := time.Now()

	fieldData := &safe.Field{
		Name:  "not before",
		Rules: safe.Rules{safe.NotBefore(now)},
	}

	invalidValues := []*invalidValue{
		{Val: now.Add(-time.Hour)},
		{Val: now.Add(-time.Minute)},
		{Val: now.Add(-time.Second)},
		{Val: now.Add(-time.Millisecond)},
		{Val: now.Add(-time.Microsecond)},
	}
	okValues := []any{
		now,
		now.Add(time.Hour),
		now.Add(time.Minute),
		now.Add(time.Second),
		now.Add(time.Millisecond),
		now.Add(time.Microsecond),
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.IlogicalDatesMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestMaxDaysRangeRule(t *testing.T) {
	now := time.Now()

	oneDayAhead := now.Add(time.Hour * 24)
	twoDaysAhead := now.Add(time.Hour * 24 * 2)
	threeDaysAhead := now.Add(time.Hour * 24 * 3)
	fourDaysAhead := now.Add(time.Hour * 24 * 4)

	oneDayAgo := now.Add(-time.Hour * 24)
	twoDaysAgo := now.Add(-time.Hour * 24 * 2)
	threeDaysAgo := now.Add(-time.Hour * 24 * 3)
	fourDaysAgo := now.Add(-time.Hour * 24 * 4)

	almostTomorrowButStillToday := now.Add(time.Hour * time.Duration(23-now.Hour()))
	almostTodayButStillYesterday := now.Add(-time.Hour * time.Duration(now.Hour()+1))

	maxDaysRange := 3

	msg := fmt.Sprintf("Período não pode ser maior que %d dias. Comparando com: %v", maxDaysRange, threeDaysAhead)

	fieldData := &safe.Field{
		Name:  "max days range",
		Rules: safe.Rules{safe.MaxDaysRange(threeDaysAhead, maxDaysRange).WithMessage(msg)},
	}

	invalidValues := []*invalidValue{
		{Val: oneDayAgo},
		{Val: twoDaysAgo},
		{Val: threeDaysAgo},
		{Val: fourDaysAgo},
		{Val: almostTodayButStillYesterday},
	}
	okValues := []any{
		now,
		oneDayAhead,
		twoDaysAhead,
		threeDaysAhead,
		fourDaysAhead,
		almostTomorrowButStillToday,
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, msg)
	testFieldWithOkValues(fieldData, okValues, t)

	msg = fmt.Sprintf("Período não pode ser maior que %d dias. Comparando com: %v", maxDaysRange, threeDaysAgo)

	fieldData.Rules = safe.Rules{safe.MaxDaysRange(threeDaysAgo, maxDaysRange).WithMessage(msg)}

	invalidValues = []*invalidValue{
		{Val: oneDayAhead},
		{Val: twoDaysAhead},
		{Val: threeDaysAhead},
		{Val: fourDaysAhead},
	}
	okValues = []any{
		now,
		oneDayAgo,
		twoDaysAgo,
		threeDaysAgo,
		fourDaysAgo,
		almostTomorrowButStillToday,
		almostTodayButStillYesterday,
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, msg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestWithMessage(t *testing.T) {
	customErrMsg := "custom err msg"
	fieldData := &safe.Field{
		Name:  "email",
		Rules: safe.Rules{safe.Email().WithMessage(customErrMsg)},
	}

	invalidValues := []*invalidValue{{Val: 0, ExpectedErrMsg: customErrMsg}}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
}
