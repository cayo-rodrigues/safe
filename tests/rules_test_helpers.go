package tests

import (
	"testing"

	"github.com/cayo-rodrigues/safe"
)

type InvalidValue struct {
	Val            any
	ExpectedErrMsg string
}

func testFieldWithOkValues(fieldData *safe.Field, validValues []any, t *testing.T) {
	for _, sampleValue := range validValues {
		fieldData.Value = sampleValue

		errors, isValid := safe.Validate(safe.Fields{fieldData})

		if !isValid {
			t.Errorf("field should be valid. %s", fieldData)

		}

		errMsg, hasErrMsg := errors[fieldData.Name]
		if hasErrMsg {
			t.Errorf("field should not be present in error messages. %s. Message: %s", fieldData, errMsg)

		}
	}
}

func testFieldWithInvalidValues(fieldData *safe.Field, invalidValues []*InvalidValue, t *testing.T, singleErrMsg ...string) {
	sharedErrMsg := ""
	if len(singleErrMsg) > 0 {
		sharedErrMsg = singleErrMsg[0]
	}

	for _, sampleValue := range invalidValues {
		fieldData.Value = sampleValue.Val

		errors, isValid := safe.Validate(safe.Fields{fieldData})

		if isValid {
			t.Errorf("field should not be valid. %s", fieldData)

		}

		errMsg, hasErrMsg := errors[fieldData.Name]
		if !hasErrMsg {
			t.Errorf("field should be present in error messages. %s", fieldData)

		}

		if sharedErrMsg != "" {
			sampleValue.ExpectedErrMsg = sharedErrMsg
		}

		if errMsg != sampleValue.ExpectedErrMsg {
			t.Errorf("error message is wrong. %s.\nExpected: %v\nGot: %v.", fieldData, sampleValue.ExpectedErrMsg, errMsg)

		}
	}
}
