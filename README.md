# Safe

> A simple Go validation library

<img src="./logo.png" width="20%" alt="Safe logo">

User input is unpredictable. Never trust it. Use this library to validate anything you want, and you know you're safe!

## Why safe?

- **No reflection.** Rules are plain functions over values. Nothing is inspected at runtime.
- **No struct tags.** Rules are Go code, so a typo is a compile error instead of a runtime surprise. Your editor autocompletes them and your compiler type checks them.
- **Validates anything, not just structs.** Function arguments, query params, a computed number, a response from a third party API. If it is a value, it can be validated.
- **Zero dependencies.** Only the standard library.
- **Allocation free validation.** Validating an already built set of fields does no heap allocations at all.
- **Conditional rules are first class.** `RequiredUnless`, `RequiredIf` and flow rules express "required only when..." without registering custom validators anywhere.
- **Localized error messages.** `PT_BR` and `EN_US` out of the box, plus any language you want to add.
- **Errors are just errors.** `safe.ErrorMessages` implements the `error` interface and marshals straight to JSON.

## Installation

```bash
go get -u github.com/cayo-rodrigues/safe
```

## Quick start

```go
fields := safe.Fields{
    {Name: "username", Value: u.Username, Rules: safe.Rules{safe.Required(), safe.Min(3)}},
    {Name: "email", Value: u.Email, Rules: safe.Rules{safe.Required(), safe.Email()}},
}

fields.SetLanguage(languages.EN_US)

if errs := safe.Validate(fields); errs != nil {
    fmt.Println(errs["email"]) // Invalid format
}
```

That's the whole idea: describe your fields, list their rules, validate. The default language is `languages.PT_BR`, so `SetLanguage` is only needed when you want a different one.

## A fuller example

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

errors := safe.Validate(fields)
```



That's it! 

In the example above, `errors` is a `safe.ErrorMessages`, which is just a wrapper around `map[string]string` that implements the `error` interface. It has error messages for each field. The default error message can be overwritten with the `WithMessage` func, as demonstrated in the example, for the email field.

When a field fails to pass a given rule, no more subsequent rules are applied. For instance, if password is not provided, it will fail the `safe.Required` rule, hence the `safe.StrongPassword` rule will not run its validation func, and the resulting error message will be regarding the absence of a value, instead of the fact that it does not conform to a strong password standard.

You can refer to the source code or the individual documentation of each function for further instructions. They are all very intuitive.

## Use cases

### Validating a request body

The most common case. Since `safe.ErrorMessages` marshals to JSON, an invalid request can be answered directly with it.

```go
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
    input := CreateUserInput{}
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "invalid body", http.StatusBadRequest)
        return
    }

    fields := safe.Fields{
        {
            Name:  "username",
            Value: input.Username,
            Rules: safe.Rules{safe.Required(), safe.Min(3), safe.Max(128)},
        },
        {
            Name:  "email",
            Value: input.Email,
            Rules: safe.Rules{safe.Required(), safe.Email()},
        },
        {
            Name:  "password",
            Value: input.Password,
            Rules: safe.Rules{safe.Required(), safe.StrongPassword()},
        },
    }

    if errs := safe.Validate(fields); errs != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        w.Write(errs.JSON())
        return
    }

    // create the user ...
}
```

Because `safe.ErrorMessages` implements the `error` interface, it also fits inside your own error types, just like any other error:

```go
type ApiError struct {
    StatusCode  int                `json:"status_code"`
    Msg         string             `json:"msg"`
    FieldErrors safe.ErrorMessages `json:"field_errors"`
}

func (e ApiError) Error() string {
    return fmt.Sprintf("Status=%d Msg='%s' FieldErrors='%s'", e.StatusCode, e.Msg, e.FieldErrors)
}
```

### Validating query params and filters

Query params are optional, loosely typed and often depend on each other. Flow rules make this straightforward: each field is only validated when it actually has a value.

```go
func ListUsersHandler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    limit, _ := strconv.Atoi(q.Get("limit"))
    offset, _ := strconv.Atoi(q.Get("offset"))

    fields := safe.Fields{
        {
            Name:  "limit",
            Value: limit,
            Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(1), safe.LessThanOrEqualTo(100)},
        },
        {
            Name:  "offset",
            Value: offset,
            Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(0)},
        },
        {
            Name:  "order_by",
            Value: q.Get("order_by"),
            Rules: safe.Rules{safe.StopIfNoValue(), safe.OneOf([]string{"created_at", "username"})},
        },
    }

    fields.SetLanguage(languages.EN_US)

    if errs := safe.Validate(fields); errs != nil {
        // ?limit=500&order_by=nope
        // {"limit":"Value must be less than or equal to 100.","order_by":"Unacceptable value"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        w.Write(errs.JSON())
        return
    }

    // list the users ...
}
```

### Validating function arguments

Values do not need to come from a struct, or from a request. They can be anything, including plain function arguments.

```go
func Transfer(fromID, toID string, amount float64) error {
    fields := safe.Fields{
        {
            Name:  "from_id",
            Value: fromID,
            Rules: safe.Rules{safe.Required(), safe.UUIDstr()},
        },
        {
            Name:  "to_id",
            Value: toID,
            Rules: safe.Rules{safe.Required(), safe.UUIDstr(), safe.NotEqualTo(fromID)},
        },
        {
            Name:  "amount",
            Value: amount,
            Rules: safe.Rules{safe.Required(), safe.GreaterThan(0.0)},
        },
    }

    if errs := safe.Validate(fields); errs != nil {
        return errs
    }

    // move the money ...
}
```

### Asserting outputs in tests

The same idea works in reverse. Instead of describing what an input must look like, describe what an output must look like.

```go
func TestInsertStuffService(t *testing.T) {
    input := StuffInputData{A: "a", B: "bb"}

    output := services.InsertStuffService(&input)

    outputShape := safe.Fields{
        {
            Name:  "output_ID",
            Value: output.ID,
            Rules: safe.Rules{safe.Required(), safe.UUIDstr()},
        },
        {
            Name:  "output_A",
            Value: output.A,
            Rules: safe.Rules{safe.Required(), safe.EqualTo(input.A)},
        },
        {
            Name:  "output_B",
            Value: output.B,
            Rules: safe.Rules{safe.Required(), safe.EqualTo(input.B)},
        },
        {
            Name:  "output_CreatedAt",
            Value: output.CreatedAt,
            Rules: safe.Rules{safe.Required()},
        },
    }

    if errs := safe.Validate(outputShape); errs != nil {
        t.Fatalf("Output does not match expected conditions.\nerrors: %s\nvalue: %s", errs, outputShape)
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

## Changing the default language

The default language is `languages.PT_BR`. To change it, do:

```go
messages.DefaultLang = languages.EN_US
```

You could also set it to some other language if you want:

```go
myLang := languages.Language("ES_LA")
messages.DefaultLang = myLang
```

But in this case, remember that you must ensure that all messages have a fallback in `myLang`.
In case no message is found in any language at all, the final fallback is `"T^T"`. It will not panic.

## Specific characteristics of rules

As already shown, rules can have their error message customized. But they can also be modified in other ways.

```go
func (rs *RuleSet) WithMessage(msg string) *RuleSet
func (rs *RuleSet) WithMessageFunc(f func(*RuleSet) string) *RuleSet
func (rs *RuleSet) WithValidateFunc(f func(*RuleSet) bool) *RuleSet
func (rs *RuleSet) WithFlowFunc(f func(*RuleSet) bool) *RuleSet
func (rs *RuleSet) WithOpts(opts RuleSetOpts) *RuleSet
```

### About RuleSetOpts

Rules can be modified by setting options to them.

```go
type RuleSetOpts struct {
    AcceptNumberZero bool
    TrimWhitespace   bool
    AllowWhitespace  bool
}
```

**`AcceptNumberZero`** — when true, the number `0` is treated as having a value. For instance, if you have a `safe.Required` rule in a field configured with `AcceptNumberZero = true`, the number `0` will pass.

```go
fields := safe.Fields{
    {
        Name: "field_1",
        Value: 0,
        Rules: safe.Rules{
            safe.Required().WithOpts(safe.RuleSetOpts{
                AcceptNumberZero: true,
            }),
        },
    },
}
```

**`TrimWhitespace`** — when true, string rules validate against the leading/trailing-trimmed value. Useful for inputs that may have been pasted with surrounding whitespace. Honored by `safe.Email`, `safe.Phone`, `safe.Cpf`, `safe.Cnpj`, `safe.CpfCnpj`, `safe.CEP`, `safe.UUIDstr`, `safe.NoWhitespace`, `safe.StrongPassword`, `safe.Match`, `safe.Min` / `safe.Max` (string case), `safe.Contains`, `safe.NotContains`, `safe.ContainsAll`, `safe.ContainsSome`, `safe.ContainsNone`, `safe.Alpha`, `safe.Numeric`, `safe.AlphaNumeric`, `safe.URL`, `safe.StrictURL`, `safe.Hex`, `safe.HexColor`.

```go
safe.Email().WithOpts(safe.RuleSetOpts{TrimWhitespace: true})
// "  user@example.com  " will now pass
```

**`AllowWhitespace`** — only relevant for the character-class rules (`safe.Alpha`, `safe.Numeric`, `safe.AlphaNumeric`, `safe.Hex`). When true, whitespace characters are accepted inside the value (e.g. `"John Doe"` passes `safe.Alpha`), but a wholly-whitespace string still fails. Note: this does *not* trim the value — the field's value is unchanged, only what counts as a valid character is loosened.

```go
safe.Alpha().WithOpts(safe.RuleSetOpts{AllowWhitespace: true})
// "Maria das Dores" passes; "   " still fails
```

In order to make things easier, `safe.Fields` exposes methods to set rule opts.

```go
func (fields *Fields) SetRuleOpts(fieldNames []string, opts RuleSetOpts) *Fields
func (fields *Fields) SetRuleOptsForAll(opts RuleSetOpts) *Fields
```

### About FlowFuncs

A rule may have a flow function. This function, if present, will be executed during the validation routine, before the
validation function. If the `FlowFunc` returns `true`, then proceed with the validation. Otherwise, stop validating the field.
There is no error message for this case. It simply stops validation.

Some rules exposed by this library are purely flow rules, with no `ValidateFunc`.

If a rule has both `FlowFunc` and `ValidateFunc`, then `FlowFunc` will take preference.


## Creating your own rules

You can also create your own rules. For instance:

```go
MyCustomRule := &safe.RuleSet{
    RuleName: "my own rule!", // this is used only for pretty printing, like fmt.Println("%s", rs)
    MessageFunc: func(rs *safe.RuleSet) string {
        // here, you can return a message for when the input is not valid
        // in case you create your own custom messages, this is the place where you could use them,
        // passing rs.Language as input
        return fmt.Sprintf("'%v'? Are you kidding?", rs.FieldValue)
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

Same thing could be done using the rule constructor with builder pattern.

```go
MyCustomRule := safe.NewRuleSet("my own rule!").
    WithMessage("r u kidding?").
    WithValidateFunc(func (rs *safe.RuleSet) bool {
        // ...
    })
```

## All Rules

This is a list of all available rules. Hopefuly their names convey their behavior. Please refer to their individual documentations.

- `safe.Required`
- `safe.True`
- `safe.False`
- `safe.Email`
- `safe.Phone`
- `safe.Cpf`
- `safe.Cnpj`
- `safe.CpfCnpj`
- `safe.CEP`
- `safe.StrongPassword`
- `safe.UUIDstr`
- `safe.NoWhitespace`
- `safe.Alpha`
- `safe.Numeric`
- `safe.AlphaNumeric`
- `safe.URL`
- `safe.StrictURL`
- `safe.Hex`
- `safe.HexColor`
- `safe.UniqueList`
- `safe.Match`
- `safe.MatchList`
- `safe.Min`
- `safe.Max`
- `safe.OneOf`
- `safe.NotOneOf`
- `safe.RequiredUnless`
- `safe.RequiredIf`
- `safe.After`
- `safe.NotAfter`
- `safe.Before`
- `safe.NotBefore`
- `safe.MaxDaysRange`
- `safe.EqualTo`
- `safe.NotEqualTo`
- `safe.GreaterThan`
- `safe.GreaterThanOrEqualTo`
- `safe.LessThan`
- `safe.LessThanOrEqualTo`
- `safe.Contains`
- `safe.NotContains`
- `safe.ContainsAll`
- `safe.ContainsSome`
- `safe.ContainsNone`


## Flow Rules

Flow rules are used the same way as normal rules. However they control the flow of the validation. Hopefuly their names describe what they do.

- `safe.StopIfNoValue`
- `safe.StopIf`
- `safe.StopIfFunc`

Here is an example:

```go
fields := safe.Fields{
    {
        Name:  "limit",
        Value: filters.Limit,
        Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(10), safe.RequiredIf(filters.Offset)},
    },
    {
        Name:  "offset",
        Value: filters.Offset,
        Rules: safe.Rules{safe.StopIfNoValue(), safe.GreaterThanOrEqualTo(0), safe.RequiredIf(filters.Limit)},
    },
    {
        Name:  "order_by",
        Value: filters.OrderBy,
        Rules: safe.Rules{safe.OneOf([]string{"created_at"})},
    },
    {
        Name:  "search",
        Value: filters.Search,
        Rules: safe.Rules{safe.Max(128)},
    },
}

fields.SetRuleOptsForAll(safe.RuleSetOpts{
    AcceptNumberZero: true,
})
```

In the example above, `filters.Limit` and `filters.Offset` will be validated only when they have a value. Otherwise, validation is skipped.

And of course, you can create your own flow rules as well.

## Helper functions

Safe exposes some helper functions that you can use, whether in the context of validation rules or not. They are:

- `safe.All`
- `safe.AllFunc`
- `safe.None`
- `safe.NoneFunc`
- `safe.Some`
- `safe.SomeFunc`
- `safe.HasValue`
- `safe.HasValue__SkipNumeric`
- `safe.AllUnique`
- `safe.IsStrongPassword`
- `safe.IsASCIIDigit`
- `safe.IsAlphaNumeric`
- `safe.IsHexDigit`
- `safe.IsCharClass`
- `safe.DifferenceInDays`
- `safe.AnyToFloat64`

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
- `safe.URLRegex` (relaxed; scheme optional)
- `safe.StrictURLRegex` (requires http:// or https://)
- `safe.HexColorRegex` (CSS hex color: `#` + 3/6/8 hex digits)
- `safe.HasUppercaseRegex`
- `safe.HasLowercaseRegex`
- `safe.HasDigitRegex`
- `safe.HasSpecialCharacterRegex`

Please refer to their individual documentations.

Regarding regexes, here is a useful repo: https://github.com/osintbrazuca/osint-brazuca-regex.
