# Safe

> A simple Go validation library

<img src="./logo.png" width="20%" alt="Safe logo">

User input is unpredictable. Never trust it. Use this library to validate anything you want, and you know you're safe!

## Installation

```bash
go get -u github.com/cayo-rodrigues/safe
```

## Usage

```go
u := &User{...}

oneYear := (time.Hour * 24) * 365
minorBirthDate := time.Now().Add(-oneYear * 18)
unavailableRoles := [2]string{"software developer", "pepsimaaaaan"}
pineappleRegex := regexp.MustCompile("^pine.*apple$")

fields := safe.Fields{
    {
        Name: "username",
        Value: u.Username,
        Rules: safe.Rules{safe.Required(), safe.Min(3), safe.Max(128)},
    },
    {
        Name: "email",
        Value: u.Email,
        Rules: safe.Rules{safe.Required(), safe.Email(), safe.Max(128).WithMessage("Is your email really that long?")},
    },
    {
        Name: "cpf/cnpj",
        Value: u.CpfCnpj,
        Rules: safe.Rules{
            safe.RequiredUnless(safe.All(u.Email, u.Username)), // cpf/cnpj is required, unless both u.Email and u.Username have a value
            safe.CpfCnpj(),
            safe.Max(128),
        },
    },
    {
        Name: "password",
        Value: u.Password,
        Rules: safe.Rules{safe.Required(), safe.StrongPassword()},
    },
    {
        Name: "roles",
        Value: u.Roles,
        Rules: safe.Rules{
            safe.UniqueList[string](), // must provide the type of the elements in the list
            safe.NotOneOf(unavailableRoles[:]), // the input must be a slice, but unavailableRoles is an array with a fixed size, that's why we need [:] here
        },
    },
    {
        Name: "birth",
        Value: u.BirthDate,
        Rules: safe.Rules{
            safe.RequiredUnless(u.CpfCnpj, u.Pineapple), // required, unless u.CpfCnpj OR u.Pineapple have a value
            safe.NotBefore(minorBirthDate)},
    },
    {
        Name: "company_id",
        Value: u.CompanyID,
        Rules: safe.Rules{
            safe.RequiredUnless(safe.CnpjRegex.MatchString(u.CpfCnpj)).WithMessage("Must provide a valid cnpj or company_id"), // got it?
            safe.UUIDstr(),
        },
    },
    {
        Name: "pineapple",
        Value: u.Pineapple,
        Rules: safe.Rules{safe.Match(pineappleRegex)},
    },
}

// this will set the language for all the error messages
// the default is languages.PT_BR
fields.SetLanguage(languages.EN_US)

errors, isValid := safe.Validate(fields)
```



That's it! 

In the example above, `errors` is a `safe.ErrorMessages`, which is just a wrapper around `map[string]string` that implements the `error` interface. It has error messages for each field. The default error message can be overwritten with the `WithMessage` func, as demonstrated in the example, for the email field.

When a field fails to pass a given rule, no more subsequent rules are applied. For instance, if password is not provided, it will fail the `safe.Required` rule, hence the `safe.StrongPassword` rule will not run its validation func, and the resulting error message will be regarding the absence of a value, instead of the fact that it does not conform to a strong password standard.

You can refer to the source code or the individual documentation of each function for further instructions. They are all very intuitive.

## Use cases

The fact that `safe.ErrorMessages` implements the `error` interface makes it possible to use it in any error handling case, just like any other error. 

For example, suppose you have a custom error you return from an http api. You could do something like this:

```go
type ApiError struct {
	StatusCode  int                `json:"status_code"`
	Msg         string             `json:"msg"`
	FieldErrors safe.ErrorMessages `json:"field_errors"`
}

func (e ApiError) Error() string {
    // ...
}
```

You could also use it for unit testing:

```go

func TestInsertStuffService(t *testing.T) {
    input := StuffInputData{
        A: "a",
        B: "bb",
    }
    output := services.InsertStuffService(&input)

    expectedOutputConditions := safe.Fields{
        {
            Name: "output_ID",
            Value: output.ID,
            Rules: safe.Rules{safe.Required(), safe.UUIDstr()},
        },
        {
            Name: "output_A",
            Value: output.A,
            Rules: safe.Rules{safe.Required(), safe.EqualTo(input.A)},
        },
        {
            Name: "output_B",
            Value: output.B,
            Rules: safe.Rules{safe.Required(), safe.EqualTo(input.B)},
        },
        {
            Name: "output_CreatedAt",
            Value: output.CreatedtAt,
            Rules: safe.Rules{safe.Required()},
        }
    }

    errors, ok := safe.Validate(expectedOutputConditions)
    if !ok {
        t.Fatalf("Output does not match expected conditions: %s", errors)
    }
}

```

## About error messages and languages

Safe exposes `messages.Messages`, which is a localized set of error messages.

You can either extend the behavior of `messages.Messages` or create your own set of messages, completely decoupled from it.

You are free to use `messages.Messages` directly or to use the shortcuts provided in the `messages` package, like `messages.MandatoryFieldMsg`, `messages.MaxValueMsg`, and so forth.
The shortcuts provide a straightforward way to access a message, with an optional `language.Language` input.

The default language used in the error messages is `languages.PT_BR`, but you can use `languages.EN_US` as well. No other languages are supported out of the box right now, but nothing stops you from creating your own! 

Here is an example of what it may look like:

```go
myLang := languages.Language("ES_LA")
myMsgKey := messages.MessageKey("myMsgKey")

myMsgPt := "my msg PT"
myMsgEn := "my msg EN"
myMsgInMyLang := "my msg arriba!"

messages.Messages.Update(messages.LocalizedMessages{
    languages.PT_BR: {
        myMsgKey: myMsgPt,
    },
    languages.EN_US: {
        myMsgKey: myMsgEn,
    },
    myLang: {
        myMsgKey: myMsgInMyLang,
    },
})

// from here onwards you can use your new message from anywhere
msg := messages.Messages.Get(myLang, myMsgKey)
```

You could also do something similar in case you want to just add a new language to the existing default messages.
For instance:

```go
newLang := languages.Language("ES_LA")

messages.Messages.Update(messages.LocalizedMessages{
    newLang: {
        messages.MsgKey__MandatoryField: "Campo obligatorio",
        messages.MsgKey__InvalidFormat: "Formato no válido",
        messages.MsgKey__UniqueList: "Los valores en la lista deben ser únicos",
    },
})

// mandatory field message in ES_LA
msg1 := messages.MandatoryFieldMsg(newLang) 

// invalid format message in ES_LA
msg2 := messages.InvalidFormatMsg(newLang) 

// illogial dates message in PT_BR, because it has not been found in the ES_LA messages
msg3 := messages.IlogicalDatesMsg(newLang) 
```



## Creating your own rules

You can also create your own rules. For instance:

```go
MyCustomRule := &safe.RuleSet{
    RuleName: "my own rule!", // this is used only for pretty printing, like fmt.Println("%s", rs)
    MessageFunc: func(rs *safe.RuleSet) string {
        // here, you can return a message for when the input is not valid
        // in case you create your own custom messages, this is the place where you could use them,
        // passing rs.Language as input
        return fmt.Sprintf("why did you input %v?", rs.FieldValue)
    },
    ValidateFunc: func(rs *safe.RuleSet) bool {
        // in this function, you may perform any validation you want!
        userInput, ok := rs.FieldValue.(string)
        if !ok {
            return false
        }

        if userInput == "" {
            return true // in case you return false, the field will be required
        }

        isValid := false
    
        // perform checks...
        
        return isValid
    },
}

someVal := "someVal"

fields := safe.Fields{
    // ...
    {
        Name: "my custom rule",
        Value: someVal,
        Rules: safe.Rules{MyCustomRule, safe.Max(256)},
    }
}
```



## Helper functions

Safe exposes some helper functions that you can use, whether in the context of validation rules or not. They are:

- `safe.All`
- `safe.HasValue`
- `safe.AllUnique`
- `safe.IsStrongPassword`
- `safe.DifferenceInDays`

Please refer to their individual documentations.

## Regexes

Safe also exposes some regexes for convenience. They are:

- `safe.WhateverRegex` (accepts literally anything)
- `safe.EmailRegex`
- `safe.PhoneRegex`
- `safe.CpfRegex`
- `safe.CnpjRegex`
- `safe.CepRegex`
- `safe.AddressNumberRegex`
- `safe.UUIDRegex`
- `safe.NoWhitespaceRegex`
- `safe.HasUppercaseRegex`
- `safe.HasLowercaseRegex`
- `safe.HasDigitRegex`
- `safe.HasSpecialCharacterRegex`

Please refer to their individual documentations.

Regarding regexes, here is a useful repo: https://github.com/osintbrazuca/osint-brazuca-regex.
