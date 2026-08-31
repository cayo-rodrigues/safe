package tests

import (
	"testing"

	"github.com/cayo-rodrigues/safe"
)

func BenchmarkValidate(b *testing.B) {
	user := newSampleUser()
	fields := sampleFields(user)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = safe.Validate(fields)
	}
}

func BenchmarkValidateWithConstruction(b *testing.B) {
	user := newSampleUser()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fields := sampleFields(user)
		_ = safe.Validate(fields)
	}
}

func BenchmarkValidateField(b *testing.B) {
	field := &safe.Field{
		Name:  "email",
		Value: "user@user.com",
		Rules: safe.Rules{safe.Required(), safe.Email(), safe.Max(128)},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = safe.ValidateField(field)
	}
}

func BenchmarkValidateInvalid(b *testing.B) {
	user := newSampleUser()
	user.Name = ""
	user.Password = "weak"
	user.CpfCnpj = "not-a-cpf-or-cnpj"
	user.Email = ""
	user.Phone = ""

	fields := sampleFields(user)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = safe.Validate(fields)
	}
}
