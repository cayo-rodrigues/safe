package strhelpers

import (
	"math/rand"
	"strings"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	"!@#$%^&*()_+-=`~.,<>?/´'\";:|{}[]"

func RandStr(length int) string {
	var s strings.Builder

	for i := 0; i < length; i++ {
		charIdx := rand.Intn(len(charset))
		char := charset[charIdx]
		s.WriteByte(char)
	}

	return s.String()
}
