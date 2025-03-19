package tests

import (
	"testing"

	"github.com/cayo-rodrigues/safe/constants/languages"
	"github.com/cayo-rodrigues/safe/messages"
)

type SimpleShortcut func(lang ...languages.Language) string

type ShortcutWithIntArg struct {
	fn  func(v int, lang ...languages.Language) string
	arg int
}

func performSimpleMessageShortcutTest(t *testing.T, key messages.MessageKey, shortcutFn SimpleShortcut, fmtArgs ...any) {
	msg := shortcutFn()
	expectedMsg := messages.Messages.Get(languages.PT_BR, key, fmtArgs...)

	if msg != expectedMsg {
		t.Fatalf("Expected msg from shortcut to be '%s', got '%s'", expectedMsg, msg)
	}

	msg = shortcutFn(languages.EN_US)
	expectedMsg = messages.Messages.Get(languages.EN_US, key, fmtArgs...)

	if msg != expectedMsg {
		t.Fatalf("Expected msg from shortcut to be '%s', got '%s'", expectedMsg, msg)
	}
}

func performMessageShortcutWithIntArgTest(t *testing.T, key messages.MessageKey, shortcut ShortcutWithIntArg) {
	msg := shortcut.fn(shortcut.arg)
	expectedMsg := messages.Messages.Get(languages.PT_BR, key, shortcut.arg)

	if msg != expectedMsg {
		t.Fatalf("Expected msg from shortcut to be '%s', got '%s'", expectedMsg, msg)
	}

	msg = shortcut.fn(shortcut.arg, languages.EN_US)
	expectedMsg = messages.Messages.Get(languages.EN_US, key, shortcut.arg)

	if msg != expectedMsg {
		t.Fatalf("Expected msg from shortcut to be '%s', got '%s'", expectedMsg, msg)
	}
}
