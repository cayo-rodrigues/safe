package tests

import (
	"testing"
	"time"

	"github.com/cayo-rodrigues/safe"
	"github.com/cayo-rodrigues/safe/internal/tests/strhelpers"
	"github.com/cayo-rodrigues/safe/messages"
)

func TestStopIfNoValueFlowRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "stop_if_no_value",
		Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(10)},
	}

	invalidValues := []*invalidValue{
		{Val: 9},
		{Val: -1},
		{Val: 1},
		{Val: 0.0001},
	}

	okValues := []any{
		"",
		nil,
		0,
		struct{}{},
		time.Time{},
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, messages.GreaterThanOrEqualToMsg(10))
	testFieldWithOkValues(fieldData, okValues, t)

	fieldData.SetRuleOpts(&safe.RuleSetOpts{
		AcceptNumberZero: true,
	})

	invalidValues = []*invalidValue{
		{Val: 0},
		{Val: 9},
		{Val: -1},
		{Val: 1},
		{Val: 0.0001},
	}

	okValues = []any{
		"",
		nil,
		struct{}{},
		time.Time{},
	}

	testFieldWithInvalidValues(fieldData, invalidValues, t, messages.GreaterThanOrEqualToMsg(10))
	testFieldWithOkValues(fieldData, okValues, t)
}

func TestStopIfFlowRule(t *testing.T) {
	fieldData := &safe.Field{
		Name:  "stop_if",
		Rules: safe.Rules{safe.StopIf(true), safe.LessThanOrEqualTo(10)},
	}

	okValues := []any{
		"",
		nil,
		0,
		struct{}{},
		time.Time{},
		strhelpers.RandStr(10),
		strhelpers.RandStr(64),
		strhelpers.RandStr(128),
		999999999,
	}

	testFieldWithOkValues(fieldData, okValues, t)
}

func TestStopIfFuncFlowRule(t *testing.T) {
	fieldData := &safe.Field{
		Name: "stop_if_func",
		Rules: safe.Rules{safe.StopIfFunc(func(fieldValue any) bool {
			n, ok := safe.AnyToFloat64(fieldValue)
			if !ok {
				return false
			}
			return n <= 10
		}), safe.EqualTo(999)},
	}

	okValues := []any{
		10,
		9,
		0,
		-1,
		-10,
	}

	invalidValues := []*invalidValue{
		{Val: 11},
		{Val: 999.000001},
		{Val: 998.9999999},
	}

	testFieldWithOkValues(fieldData, okValues, t)
	testFieldWithInvalidValues(fieldData, invalidValues, t, messages.UnacceptableValueMsg())
}
