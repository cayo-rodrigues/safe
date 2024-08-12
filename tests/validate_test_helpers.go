package tests

import "github.com/cayo-rodrigues/safe"

type SampleUser struct {
	ID       string
	Name     string
	Email    string
	Phone    string
	CpfCnpj  string
	Password string
	Age      int
	Job      string
	*Address
}

type Address struct {
	Street       string
	Number       string
	Cep          string
	Neighborhood string
	City         string
	State        string
}

func newSampleUser() *SampleUser {
	return &SampleUser{
		ID:       "f51abc35-4aa1-439b-a985-6d56439901d9",
		Name:     "some random name rodriguez",
		Email:    "user@user.com",
		Phone:    "+55 99988-7766",
		CpfCnpj:  "85.200.013/0001-67",
		Password: "^123!q@w#e4R5T6Y$",
		Age:      25,
		Job:      "software developer",
		Address: &Address{
			Street:       "Praça Coronel Ernesto Muniz Barreto",
			Number:       "15",
			Cep:          "49750-970",
			Neighborhood: "brotherhood",
		},
	}
}

func sampleJobs() []string {
	return []string{"software developer", "designer", "devops engineer", "po", "techlead", "scrum master", "ceo", "marketing", "sales", "cs", "spider-man", ""}
}

func sampleFields(user *SampleUser) safe.Fields {
	return safe.Fields{
		{
			Name:  "id",
			Value: user.ID,
			Rules: safe.Rules{safe.Required(), safe.UUIDstr()},
		},
		{
			Name:  "name",
			Value: user.Name,
			Rules: safe.Rules{safe.Required(), safe.Max(128), safe.Min(3)},
		},
		{
			Name:  "email",
			Value: user.Email,
			Rules: safe.Rules{safe.Email(), safe.RequiredUnless(user.CpfCnpj, user.Phone)},
		},
		{
			Name:  "phone",
			Value: user.Phone,
			Rules: safe.Rules{safe.Phone(), safe.RequiredUnless(user.Email, user.CpfCnpj)},
		},
		{
			Name:  "cpf/cnpj",
			Value: user.CpfCnpj,
			Rules: safe.Rules{safe.CpfCnpj(), safe.RequiredUnless(user.Email, user.Phone)},
		},
		{
			Name:  "password",
			Value: user.Password,
			Rules: safe.Rules{safe.Required(), safe.StrongPassword()},
		},
		{
			Name:  "age",
			Value: user.Age,
			Rules: safe.Rules{safe.Min(18), safe.Max(60)},
		},
		{
			Name:  "job",
			Value: user.Job,
			Rules: safe.Rules{safe.OneOf(sampleJobs())},
		},
		{
			Name:  "address_street",
			Value: user.Address.Street,
			Rules: safe.Rules{safe.Required(), safe.Max(128)},
		},
		{
			Name:  "address_number",
			Value: user.Address.Number,
			Rules: safe.Rules{safe.Required(), safe.Match(safe.AddressNumberRegex)},
		},
		{
			Name:  "address_neighborhood",
			Value: user.Address.Neighborhood,
			Rules: safe.Rules{safe.Required(), safe.Max(128)},
		},
		{
			Name:  "address_city",
			Value: user.Address.City,
			Rules: safe.Rules{safe.RequiredUnless(user.Address.Cep), safe.Max(128)},
		},
		{
			Name:  "address_state",
			Value: user.Address.State,
			Rules: safe.Rules{safe.RequiredUnless(user.Address.Cep), safe.Max(2)},
		},
		{
			Name:  "address_cep",
			Value: user.Address.Cep,
			Rules: safe.Rules{safe.CEP()},
		},
	}
}
