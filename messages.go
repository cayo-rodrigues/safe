package safe

import "fmt"

const (
	MandatoryFieldMsg    = "Campo obrigatório"
	ValueTooLongMsg      = "Valor maior do que o suportado"
	InvalidFormatMsg     = "Formato inválido"
	IlogicalDatesMsg     = "Data inicial deve ser anterior à final"
	UnacceptableValueMsg = "Valor inaceitável"
	UniqueListMsg        = "Valores na lista devem ser únicos"
	WeakPasswordMsg      = "Senha deve ter 8+ caracteres, letras minúsculas e maiúsculas, números e símbolos"
)

func MinValueMsg(minValue int) string {
	return fmt.Sprintf("Valor mínimo: %d", minValue)
}

func MinCharsMsg(minValue int) string {
	return fmt.Sprintf("Mínimo de %d caracteres", minValue)
}

func MaxValueMsg(maxValue int) string {
	return fmt.Sprintf("Valor máximo: %d", maxValue)
}

func MaxCharsMsg(maxValue int) string {
	return fmt.Sprintf("Máximo de %d caracteres", maxValue)
}

func MaxDaysRangeMsg(maxDays int) string {
	return fmt.Sprintf("Período não pode ser maior que %d dias.", maxDays)
}
