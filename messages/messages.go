package messages

import (
	"fmt"

	"github.com/cayo-rodrigues/safe/constants/languages"
)

// This is just a wrapper around string.
//
// It encorages the usage of "enums", just like the ones exported in this package.
type MessageKey string

// This is a MessageKey to be used in a MessageMap
const (
	MsgKey__MandatoryField       MessageKey = "MsgKey__MandatoryField"
	MsgKey__ValueTooLong         MessageKey = "MsgKey__ValueTooLong"
	MsgKey__InvalidFormat        MessageKey = "MsgKey__InvalidFormat"
	MsgKey__IlogicalDates        MessageKey = "MsgKey__IlogicalDates"
	MsgKey__UnacceptableValue    MessageKey = "MsgKey__UnacceptableValue"
	MsgKey__UniqueList           MessageKey = "MsgKey__UniqueList"
	MsgKey__WeakPassword         MessageKey = "MsgKey__WeakPassword"
	MsgKey__MinValue             MessageKey = "MsgKey__MinValue"
	MsgKey__MaxValue             MessageKey = "MsgKey__MaxValue"
	MsgKey__MinChars             MessageKey = "MsgKey__MinChars"
	MsgKey__MaxChars             MessageKey = "MsgKey__MaxChars"
	MsgKey__MaxDaysRange         MessageKey = "MsgKey__MaxDaysRange"
	MsgKey__Contains             MessageKey = "MsgKey__MustContain"
	MsgKey__ContainsAll          MessageKey = "MsgKey__MustContainAll"
	MsgKey__ContainsSome         MessageKey = "MsgKey__MustContainSome"
	MsgKey__NotContains          MessageKey = "MsgKey__MustNotContain"
	MsgKey__ContainsNone         MessageKey = "MsgKey__MustNotContainAny"
	MsgKey__GreaterThan          MessageKey = "MsgKey__GreaterThan"
	MsgKey__LessThan             MessageKey = "MsgKey__LessThan"
	MsgKey__GreaterThanOrEqualTo MessageKey = "MsgKey__GreaterThanOrEqualTo"
	MsgKey__LessThanOrEqualTo    MessageKey = "MsgKey__LessThanOrEqualTo"
)

// A wrapper around a map, whose purpose is to store messages by a key
//
// The message string may contain placeholders.
//
// These placeholders are used by the LocalizedMessages.Get method, in a call to fmt.Sprintf
type MessageMap map[MessageKey]string

// Messages by language
//
// A default set of messages used by the rule sets is already exported in the
// messages.Messages variable
type LocalizedMessages map[languages.Language]MessageMap

// Merge two LocalizedMessages objects together. You may use any languages you want.
func (m *LocalizedMessages) Update(localizedMsgs LocalizedMessages) {
	for lang, messageMap := range localizedMsgs {
		if _, exists := (*m)[lang]; !exists {
			(*m)[lang] = MessageMap{}
		}
		for key, msg := range messageMap {
			(*m)[lang][key] = msg
		}
	}
}

// Retrieve a message string by language and message key. You can provide additional arguments
// that will be passed to fmt.Sprintf in case the message has placeholders
func (m LocalizedMessages) Get(lang languages.Language, key MessageKey, fmtArgs ...any) string {
	if langMsgs, exists := m[lang]; exists {
		if msg, found := langMsgs[key]; found {
			if len(fmtArgs) > 0 {
				return fmt.Sprintf(msg, fmtArgs...)
			} else {
				return msg
			}
		}
	}

	if msgInDefaultLang, ok := Messages[DefaultLang][key]; ok {
		if len(fmtArgs) > 0 {
			return fmt.Sprintf(msgInDefaultLang, fmtArgs...)
		} else {
			return msgInDefaultLang
		}
	}

	return "T^T"
}

// Default language to be used as fallback if no language is set directly, or if no message is found
// when looking for a message key.
//
// # You are free to change this value
//
// In case no message is found even in the default language, the final fallback is "T^T".
// It will not panic.
var DefaultLang = languages.DEFAULT

// Messages used by the rule sets. They are available in languages.PT_BR and languages.EN_US.
//
// In case you want to use the default messages which this variable holds, it is recommended
// to use the shorcuts defined in this package instead of directly referencing this global
// variable.
//
// These messages can be extended by using the LocalizedMessages.Update method. This way
// you can create your own messages, with your own set of languages and create your own shorcuts!
var Messages = LocalizedMessages{
	languages.PT_BR: {
		MsgKey__MandatoryField:       "Campo obrigatório",
		MsgKey__ValueTooLong:         "Valor maior do que o suportado",
		MsgKey__InvalidFormat:        "Formato inválido",
		MsgKey__IlogicalDates:        "Data inicial deve ser anterior à final",
		MsgKey__UnacceptableValue:    "Valor inaceitável",
		MsgKey__UniqueList:           "Valores na lista devem ser únicos",
		MsgKey__WeakPassword:         "Senha deve ter 8+ caracteres, letras minúsculas e maiúsculas, números e símbolos",
		MsgKey__MinValue:             "Valor mínimo: %d",
		MsgKey__MaxValue:             "Valor máximo: %d",
		MsgKey__MinChars:             "Mínimo de %d caracteres",
		MsgKey__MaxChars:             "Máximo de %d caracteres",
		MsgKey__MaxDaysRange:         "Período não pode ser maior que %d dias.",
		MsgKey__Contains:             "Texto deve conter '%s'.",
		MsgKey__NotContains:          "Texto não deve conter '%s'.",
		MsgKey__ContainsNone:         "Texto não deve conter nenhuma das expressões: '%s'.",
		MsgKey__ContainsAll:          "Texto deve conter todas as expressões: '%s'.",
		MsgKey__ContainsSome:         "Texto deve conter pelo menos uma das expressões: '%s'.",
		MsgKey__GreaterThan:          "Valor deve ser maior que %v.",
		MsgKey__GreaterThanOrEqualTo: "Valor deve ser maior ou igual a %v.",
		MsgKey__LessThan:             "Valor deve ser menor que %v.",
		MsgKey__LessThanOrEqualTo:    "Valor deve ser menor ou igual a %v.",
	},
	languages.EN_US: {
		MsgKey__MandatoryField:       "Mandatory field",
		MsgKey__ValueTooLong:         "Value exceeds supported length",
		MsgKey__InvalidFormat:        "Invalid format",
		MsgKey__IlogicalDates:        "Start date must be before end date",
		MsgKey__UnacceptableValue:    "Unacceptable value",
		MsgKey__UniqueList:           "Values in the list must be unique",
		MsgKey__WeakPassword:         "Password must have 8+ characters, uppercase and lowercase letters, numbers, and symbols",
		MsgKey__MinValue:             "Minimum value: %d",
		MsgKey__MaxValue:             "Maximum value: %d",
		MsgKey__MinChars:             "Minimum of %d characters",
		MsgKey__MaxChars:             "Maximum of %d characters",
		MsgKey__MaxDaysRange:         "Period cannot exceed %d days.",
		MsgKey__Contains:             "Text must contain '%s'",
		MsgKey__NotContains:          "Text must not contain '%s'.",
		MsgKey__ContainsNone:         "Text must not contain any of the expressions: '%s'.",
		MsgKey__ContainsAll:          "Text must contain all expressions: '%s'.",
		MsgKey__ContainsSome:         "Text must contain at least one of the expressions: '%s'.",
		MsgKey__GreaterThan:          "Value must be greater than %v.",
		MsgKey__GreaterThanOrEqualTo: "Value must be greater than or equal to %v.",
		MsgKey__LessThan:             "Value must be less than %v.",
		MsgKey__LessThanOrEqualTo:    "Value must be less than or equal to %v.",
	},
}
