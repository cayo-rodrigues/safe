package safe

import "regexp"

var EmailRegex = regexp.MustCompile(`[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`)
var PhoneRegex = regexp.MustCompile(`(?:(?:\+|00)?(55)\s?)?(?:\(?([1-9][0-9])\)?\s?)(?:((?:9\d|[2-9])\d{3})\-?(\d{4}))`)
var WhateverRegex = regexp.MustCompile(`.*`)
var IEMGRegex = regexp.MustCompile(`^\d{3}.?\d{3}.?\d{3}\/?\d{4}$`)
var CPFRegex = regexp.MustCompile(`^\d{3}.?\d{3}.?\d{3}\-?\d{2}$`)
var CNPJRegex = regexp.MustCompile(`^(\d{2}.?\d{3}.?\d{3}\/?\d{4}\-?\d{2})$`)
var CEPRegex = regexp.MustCompile(`(^\d{5})\-?(\d{3}$)`)
var AddressNumberRegex = regexp.MustCompile(`^(?:s\/n|S\/n|S\/N|s\/N)|^(\d)*$`)
