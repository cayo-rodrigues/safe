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

func TestPixRule(t *testing.T) {
	t.SkipNow()

	fieldData := &safe.Field{
		Name:  "pix",
		Rules: safe.Rules(safe.Pix),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "aaa"},
	}
	okValues := []any{
		"$s3NH@!X",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.WeakPasswordMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestRandomPixRule(t *testing.T) {
	t.SkipNow()

	fieldData := &safe.Field{
		Name:  "pix",
		Rules: safe.Rules(safe.RandomPix),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "aaa"},
	}
	okValues := []any{
		"$s3NH@!X",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.WeakPasswordMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestUUIDRule(t *testing.T) {
	t.SkipNow()

	fieldData := &safe.Field{
		Name:  "pix",
		Rules: safe.Rules(safe.RandomPix),
	}

	invalidValues := []*InvalidValue{
		{Val: " "},
		{Val: "123"},
		{Val: "aaa"},
	}
	okValues := []any{
		"$s3NH@!X",
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.WeakPasswordMsg)
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestUniqueListRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "unique list",
		Rules: safe.Rules(safe.UniqueList[any]),
	}

	invalidValues := []*InvalidValue{
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
		Rules: safe.Rules(safe.Match(safe.WhateverRegex)),
	}

	invalidValues := []*InvalidValue{}
	okValues := []any{"literaly anything"}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)

	fieldData.Rules = safe.Rules(safe.Match(safe.AddressNumberRegex))

	invalidValues = []*InvalidValue{
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
		Rules: safe.Rules(safe.MatchList(safe.WhateverRegex)),
	}

	invalidValues := []*InvalidValue{}
	okValues := []any{
		[]string{"literaly anything", "whatever"},
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.InvalidFormatMsg)
	testFieldWithOkValues(fieldData, okValues, t)

	fieldData.Rules = safe.Rules(safe.MatchList(safe.AddressNumberRegex))

	invalidValues = []*InvalidValue{
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
		Rules: safe.Rules(safe.Min(minValue)),
	}

	invalidValues := []*InvalidValue{
		{Val: 4},
		{Val: 0},
		{Val: -5},
		{Val: -6},
		{Val: 4.9999},
	}
	okValues := []any{5, 6}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MinValueMsg(minValue))
	testFieldWithOkValues(fieldData, okValues, t)

	invalidValues = []*InvalidValue{
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
		Rules: safe.Rules(safe.Max(maxValue)),
	}

	invalidValues := []*InvalidValue{
		{Val: 1.000001},
		{Val: 1.1},
		{Val: 100},
	}
	okValues := []any{0, 0.5, 0.999, -1, -100}

	testFieldWithInvalidValues(fieldData, invalidValues, t, safe.MaxValueMsg(maxValue))
	testFieldWithOkValues(fieldData, okValues, t)

	invalidValues = []*InvalidValue{
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
		Rules: safe.Rules(safe.OneOf([]any{"1", "2", "abc", 123, 99.9, "abc"})),
	}

	invalidValues := []*InvalidValue{
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
		Name:  "no one of",
		Rules: safe.Rules(safe.NotOneOf([]any{"1", "2", "abc", 123, 99.9, "abc"})),
	}

	invalidValues := []*InvalidValue{
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
		Rules: safe.Rules(safe.RequiredUnless(nil)),
	}

	invalidValues := []*InvalidValue{
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

	fieldData.Rules = safe.Rules(safe.RequiredUnless("", nil, 0, struct{}{}, 0.01))

	okValues = []any{"", 0, " ", nil, 1000, "anything", time.Now(), time.Time{}}

	testFieldWithOkValues(fieldData, okValues, t)
}

func TestAfterRule(t *testing.T) {
	now := time.Now()

	fieldData := &safe.Field{
		Name:  "after",
		Rules: safe.Rules(safe.After(now)),
	}

	invalidValues := []*InvalidValue{
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
		Rules: safe.Rules(safe.NotAfter(now)),
	}

	invalidValues := []*InvalidValue{
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
		Rules: safe.Rules(safe.Before(now)),
	}

	invalidValues := []*InvalidValue{
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
		Rules: safe.Rules(safe.NotBefore(now)),
	}

	invalidValues := []*InvalidValue{
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
		Rules: safe.Rules(safe.MaxDaysRange(threeDaysAhead, maxDaysRange)().WithMessage(msg)),
	}

	invalidValues := []*InvalidValue{
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

	fieldData.Rules = safe.Rules(safe.MaxDaysRange(threeDaysAgo, maxDaysRange)().WithMessage(msg))

	invalidValues = []*InvalidValue{
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
		Rules: safe.Rules(safe.Email().WithMessage(customErrMsg)),
	}

	invalidValues := []*InvalidValue{{Val: 0, ExpectedErrMsg: customErrMsg}}

	testFieldWithInvalidValues(fieldData, invalidValues, t)
}
