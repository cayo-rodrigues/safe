package tests

import (
	"math/rand"
	"testing"

	"github.com/cayo-rodrigues/safe/constants/languages"
	"github.com/cayo-rodrigues/safe/internal/tests/strhelpers"
	"github.com/cayo-rodrigues/safe/messages"
)

func TestLocalizedMessages(t *testing.T) {
	myLang := languages.Language("ES_LA")
	myMsgKey := messages.MessageKey("myMsgKey")
	someOtherMsgKey := messages.MessageKey("otherKey")
	unusedKey := messages.MessageKey("unusedKey")

	myMsgPt := "my msg PT"
	myMsgEn := "my msg EN"
	myMsgEs := "my msg arriba!"

	otherMsgPt := "other msg PT"
	otherMsgEn := "other msg EN"

	messages.Messages.Update(messages.LocalizedMessages{
		languages.PT_BR: {
			myMsgKey:        myMsgPt,
			someOtherMsgKey: otherMsgPt,
		},
		languages.EN_US: {
			myMsgKey:        myMsgEn,
			someOtherMsgKey: otherMsgEn,
		},
		myLang: {
			myMsgKey: myMsgEs,
		},
	})

	got := messages.Messages.Get(myLang, myMsgKey)
	if got != myMsgEs {
		t.Fatalf("Expected message in lang '%s' to be '%s', got '%s'", myLang, myMsgEs, got)
	}

	got = messages.Messages.Get(languages.PT_BR, myMsgKey)
	if got != myMsgPt {
		t.Fatalf("Expected message in lang '%s' to be '%s', got '%s'", languages.PT_BR, myMsgPt, got)
	}

	got = messages.Messages.Get(languages.EN_US, myMsgKey)
	if got != myMsgEn {
		t.Fatalf("Expected message in lang '%s' to be '%s', got '%s'", languages.EN_US, myMsgEn, got)
	}

	got = messages.Messages.Get(myLang, someOtherMsgKey)
	if got != otherMsgPt {
		t.Fatalf("Expected message in lang '%s' to fallback to '%s', got '%s'", myLang, otherMsgPt, got)
	}

	messages.DefaultLang = languages.EN_US

	got = messages.Messages.Get(myLang, someOtherMsgKey)
	if got != otherMsgEn {
		t.Fatalf("Expected message in lang '%s' to fallback to '%s', got '%s'", myLang, otherMsgEn, got)
	}

	got = messages.Messages.Get(myLang, unusedKey)
	expected := "T^T"
	if got != expected {
		t.Fatalf("Expected message in lang '%s' to fallback to '%s', got '%s'", expected, myLang, got)
	}
}

func TestMessagesShortcuts(t *testing.T) {
	messages.DefaultLang = languages.DEFAULT

	simpleShortcuts := map[messages.MessageKey]SimpleShortcut{
		messages.MsgKey__MandatoryField:    messages.MandatoryFieldMsg,
		messages.MsgKey__ValueTooLong:      messages.ValueTooLongMsg,
		messages.MsgKey__InvalidFormat:     messages.InvalidFormatMsg,
		messages.MsgKey__IlogicalDates:     messages.IlogicalDatesMsg,
		messages.MsgKey__UnacceptableValue: messages.UnacceptableValueMsg,
		messages.MsgKey__UniqueList:        messages.UniqueListMsg,
		messages.MsgKey__WeakPassword:      messages.WeakPasswordMsg,
	}

	for key, fn := range simpleShortcuts {
		performSimpleMessageShortcutTest(t, key, fn)
	}

	ceil := 100_000

	shortcutsWithArgs := map[messages.MessageKey]ShortcutWithArg[int]{
		messages.MsgKey__MinValue:             {fn: messages.MinValueMsg, arg: rand.Intn(ceil)},
		messages.MsgKey__MinChars:             {fn: messages.MinCharsMsg, arg: rand.Intn(ceil)},
		messages.MsgKey__MaxValue:             {fn: messages.MaxValueMsg, arg: rand.Intn(ceil)},
		messages.MsgKey__MaxChars:             {fn: messages.MaxCharsMsg, arg: rand.Intn(ceil)},
		messages.MsgKey__MaxDaysRange:         {fn: messages.MaxDaysRangeMsg, arg: rand.Intn(ceil)},
		messages.MsgKey__GreaterThan:          {fn: messages.GreaterThanMsg[int], arg: rand.Intn(ceil)},
		messages.MsgKey__LessThan:             {fn: messages.LessThanMsg[int], arg: rand.Intn(ceil)},
		messages.MsgKey__GreaterThanOrEqualTo: {fn: messages.GreaterThanOrEqualToMsg[int], arg: rand.Intn(ceil)},
		messages.MsgKey__LessThanOrEqualTo:    {fn: messages.LessThanOrEqualToMsg[int], arg: rand.Intn(ceil)},
	}

	for key, shortcut := range shortcutsWithArgs {
		performMessageShortcutWithArgTest(t, key, shortcut)
	}

	strLen := 10

	shortcutsWithStrArgs := map[messages.MessageKey]ShortcutWithArg[string]{
		messages.MsgKey__Contains:    {fn: messages.ContainsMsg, arg: strhelpers.RandStr(strLen)},
		messages.MsgKey__NotContains: {fn: messages.NotContainsMsg, arg: strhelpers.RandStr(strLen)},
	}

	for key, shortcut := range shortcutsWithStrArgs {
		performMessageShortcutWithArgTest(t, key, shortcut)
	}

	argsCount := 3
	args := [][]string{}

	for i := 0; i < argsCount; i++ {
		args = append(args, []string{
			strhelpers.RandStr(strLen),
			strhelpers.RandStr(strLen),
			strhelpers.RandStr(strLen),
		})
	}

	shortcutsWithSliceStrArgs := map[messages.MessageKey]ShortcutWithArg[[]string]{
		messages.MsgKey__ContainsAll:  {fn: messages.ContainsAllMsg, arg: args[0]},
		messages.MsgKey__ContainsSome: {fn: messages.ContainsSomeMsg, arg: args[1]},
		messages.MsgKey__ContainsNone: {fn: messages.ContainsNoneMsg, arg: args[2]},
	}

	for key, shortcut := range shortcutsWithSliceStrArgs {
		performMessageShortcutWithArgTest(t, key, shortcut)
	}
}
