package safe

// Expects Fields, which is just a []*Field. Each Field has a slice of Rules.
// All of them are evalueted sequentially.
//
// When a Field is not valid, no more validations are performed for that specific field,
// so we proceed to the next one.
//
// Validate returns ErrorMessages, a map in which the keys correspond
// to the Field.Name property, and the values are string error messages
// according to the broken rule. When all fields are valid, ErrorMessages is nil.
//
// ErrorMessages implements the error interface.
//
// Example usage:
//
//	fields := safe.Fields{
//		{...}
//	}
//	errors := Validate(fields)
//
//	fmt.Println("are all fields valid?", errors == nil)
//	fmt.Println("what are the error messages?", errors)
func Validate(fields Fields) ErrorMessages {
	var messages ErrorMessages

	for _, field := range fields {
		for _, rs := range field.Rules {
			rs.FieldValue = field.Value

			if rs.FlowFunc != nil {
				shouldProceed := rs.FlowFunc(rs)
				if shouldProceed {
					continue // continue to the next rule
				}
				break // stop validation for this field
			}

			if rs.ValidateFunc == nil {
				continue // continue to the next rule
			}

			isValid := rs.ValidateFunc(rs)
			if !isValid {
				if messages == nil {
					messages = make(ErrorMessages)
				}
				msg := rs.MessageFunc(rs)
				messages[field.Name] = msg
				break // stop runing validate funcs after first fail
			}
		}
	}

	return messages
}
