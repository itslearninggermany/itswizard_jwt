package itswizard_jwt

type JwtClaimsStruct struct {
	Admin               bool   `json:"Admin"`
	Authenticated       bool   `json:"Authenticated"`
	Email               string `json:"Email"`
	FirstAuthentication bool   `json:"FirstAuthentication"`
	Firstname           string `json:"Firstname"`
	Information         string `json:"Information"`
	Institution         string `json:"Institution"`
	InstitutionID       uint   `json:"InstitutionID"`
	IPAddress           string `json:"IpAddress"`
	Lastname            string `json:"Lastname"`
	Mobile              string `json:"Mobile"`
	OrganisationID      uint   `json:"OrganisationID"`
	School              string `json:"School"`
	TwoFac              bool   `json:"TwoFac"`
	UserID              uint   `json:"UserID"`
	Username            string `json:"Username"`
	Exp                 int    `json:"exp"`
	Iat                 int    `json:"iat"`
}
