package messages

import "github.com/cayo-rodrigues/safe/constants/languages"

func getLang(lang ...languages.Language) languages.Language {
	if len(lang) == 0 {
		return DefaultLang
	}

	return lang[0]
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func MandatoryFieldMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__MandatoryField)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func ValueTooLongMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__ValueTooLong)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func InvalidFormatMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__InvalidFormat)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func IlogicalDatesMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__IlogicalDates)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func UnacceptableValueMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__UnacceptableValue)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func UniqueListMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__UniqueList)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func WeakPasswordMsg(lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__WeakPassword)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func MinValueMsg(minValue int, lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__MinValue, minValue)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func MinCharsMsg(minChars int, lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__MinChars, minChars)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func MaxValueMsg(maxValue int, lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__MaxValue, maxValue)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func MaxCharsMsg(maxChars int, lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__MaxChars, maxChars)
}

// A shortcut to get a message from the global messages.Messages variable
// 
// If no language is provided, messages.DefaultLang is used as default
func MaxDaysRangeMsg(maxDays int, lang ...languages.Language) string {
	return Messages.Get(getLang(lang...), MsgKey__MaxDaysRange, maxDays)
}
