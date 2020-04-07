package itswizard_jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type data struct {
	Email          string `json:"Email"`
	OrganisationID int    `json:"OrganisationID"`
	Exp            int    `json:"exp"`
	FirstName      string `json:"firstName"`
	Iat            int    `json:"iat"`
	LastName       string `json:"lastName"`
	Role           string `json:"role"`
	User           string `json:"user"`
}

func base64url_decode(b []byte) ([]byte, error) {
	if len(b)%4 != 0 {
		b = append(b, bytes.Repeat([]byte{'='}, 4-(len(b)%4))...)
	}
	decoded, err := base64.URLEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func decodePayload(input string) (jwtdata data, err error) {
	a, err := base64url_decode([]byte(input))
	if err != nil {
		return
	}
	fmt.Println(string(a))
	err = json.Unmarshal(a, &jwtdata)
	if err != nil {
		return
	}
	return
}
