# Safe

> A simple Go validation library



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

errors, isValid := safe.Validate(fields)
```



That's it! 

In the example above, `errors` is a `map[string]string` with error messages for each field. The default error message can be overwritten with the `WithMessage` func, as demonstrated in the example, for the email field.

When a field fails to pass a given rule, no more subsequent rules are applied. For instance, if password is not provided, it will fail the `safe.Required` rule, hence the `safe.StrongPassword` rule will not run its validation func, and the resulting error message will be regarding the absence of a value, instead of the fact that it does not conform to a strong password standard.

You can refer to the source code or the individual documentation of each function for further instructions. They are all very intuitive.

## Creating your own rules

You can also create your own rules. For instance:

```go
MyCustomRule := &safe.RuleSet{
	RuleName: "my own rule!", // this is used only for pretty printing, like fmt.Println("%s", rs)
	MessageFunc: func(rs *safe.RuleSet) string {
        // here, you can return a message for when the input is not valid
		return fmt.Sprintf("why did you input %v? please colaborate", rs.FieldValue)
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
- `safe.DaysDifference`

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

Please refer to their individual documentations.

Regarding regexes, here is a useful repo: https://github.com/osintbrazuca/osint-brazuca-regex.
