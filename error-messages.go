package safe

import (
	"encoding/json"
	"log"
)

// safe.Validate returns (safe.ErrorMessages, bool).
//
// safe.ErrorMessages is a map of field names, each associated with a message.
//
// Example:
//
//	fields := safe.Fields{
//		{...}
//	}
//	errors, ok := Validate(fields)
//
//	if !ok {
//		fmt.Println("why is username not valid?", errors["Username"])
//		fmt.Println("why is email not valid?", errors["Email"])
//	}
type ErrorMessages map[string]string

// Implements the error interface. Calls the JSON method and converts it to string.
func (errors *ErrorMessages) Error() string {
	return string(errors.JSON())
}

// Returns the JSON version of ErrorMessages
//
// In case of error, returns an empty []byte
func (errors *ErrorMessages) JSON() []byte {
	errorsJson, err := json.Marshal(errors)
	if err != nil {
		log.Printf("Could not marshal ErrorMessages to json: %v\n", err)
		return []byte{}
	}
	return errorsJson
}
