package safe

import "regexp"

// literally accept anything
var WhateverRegex = regexp.MustCompile(`.*`)

var EmailRegex = regexp.MustCompile(`[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+`)

var PhoneRegex = regexp.MustCompile(`(?:(?:\+|00)?(55)\s?)?(?:\(?([1-9][0-9])\)?\s?)(?:((?:9\d|[2-9])\d{3})\-?(\d{4}))`)

var IeMgRegex = regexp.MustCompile(`^\d{3}.?\d{3}.?\d{3}\/?\d{4}$`)

var CpfRegex = regexp.MustCompile(`^\d{3}.?\d{3}.?\d{3}\-?\d{2}$`)

var CnpjRegex = regexp.MustCompile(`^(\d{2}.?\d{3}.?\d{3}\/?\d{4}\-?\d{2})$`)

var CepRegex = regexp.MustCompile(`(^\d{5})\-?(\d{3}$)`)

// numbers or "S/N", "s/n", "S/n", "s/N"
var AddressNumberRegex = regexp.MustCompile(`^(?:s\/n|S\/n|S\/N|s\/N)|^(\d)*$`)

// 8-20 characters, both lowercase and uppercase letters, numbers and special characters
var StrongPasswordRegex = regexp.MustCompile(`^(?=.*[A-Z])(?=.*[a-z])(?=.*[\d])(?=.*[@#$%&*!-+&*]).{8,20}$`)

var UUIDRegex = regexp.MustCompile(`(^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$)`)

var PixRegex = regexp.MustCompile(`([0-9]{14})(br.gov.bcb.(|-)pix).*(6304)([0-9a-zA-Z]{4})`)

var RandomPixRegex = regexp.MustCompile(`([a-z\d]{8})\-([a-z\d]{4})\-([a-z\d]{4})\-([a-z\d]{4})\-([a-z\d]{12})`)
