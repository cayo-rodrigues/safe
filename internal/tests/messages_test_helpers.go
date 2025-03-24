package tests

import (
	"testing"

	"github.com/cayo-rodrigues/safe/constants/languages"
	"github.com/cayo-rodrigues/safe/messages"
)

type SimpleShortcut func(lang ...languages.Language) string

type ShortcutWithArg[T int | string | []string] struct {
	fn  func(v T, lang ...languages.Language) string
	arg T
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

func performMessageShortcutWithArgTest[T int | string | []string](t *testing.T, key messages.MessageKey, shortcut ShortcutWithArg[T]) {
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
