package safe

type Fields []*struct {
	Name  string
	Value any
	Rules []*RuleSet
}
type ErrorMessages map[string]string

func Validate(fields Fields) (ErrorMessages, bool) {
	var messages ErrorMessages

	for _, field := range fields {
		for _, rs := range field.Rules {
			rs.FieldValue = field.Value
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

	return messages, len(messages) == 0
}
