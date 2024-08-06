package safe

import "regexp"

// literally accept anything
var WhateverRegex = regexp.MustCompile(`.*`)

var EmailRegex = regexp.MustCompile(`[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`)

// with or without symbols (+-()) and whitespaces
var PhoneRegex = regexp.MustCompile(`(?:(?:\+|00)?(55)\s?)?(?:\(?([1-9][0-9])\)?\s?)(?:((?:9\d|[2-9])\d{3})\-?(\d{4}))`)

// with or without symbols (.-/)
var CpfRegex = regexp.MustCompile(`^\d{3}.?\d{3}.?\d{3}\-?\d{2}$`)

// with or without symbols (.-/)
var CnpjRegex = regexp.MustCompile(`^(\d{2}.?\d{3}.?\d{3}\/?\d{4}\-?\d{2})$`)

// with or without dash (-)
var CepRegex = regexp.MustCompile(`(^\d{5})\-?(\d{3}$)`)

// numbers or "S/N", "s/n", "S/n", "s/N"
var AddressNumberRegex = regexp.MustCompile(`^(?:s\/n|S\/n|S\/N|s\/N)|^(\d)*$`)

var UUIDRegex = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-(1|4|5|7)[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
