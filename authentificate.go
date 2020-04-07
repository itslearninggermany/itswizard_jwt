package itswizard_jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/itslearninggermany/uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
	"strings"
	"time"
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

func ReAuthentificate(r *http.Request, dbWebserver *gorm.DB) (string, error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return "", err
	}
	var payload string
	erg := strings.Split(auth.IDToken, ".")
	if len(erg) != 3 {
		return "", err
	} else {
		payload = erg[1]
	}
	jwtClaims, err := decodePayload(payload)

	exp := time.Unix(int64(jwtClaims.Exp), 0)
	if time.Now().Sub(exp) > 0 {

		fmt.Println("Refresh den Cookie")

		/*
			if CheckRefreshToken("asdasd") {
				_, jwtString, err = CreateToken("username")
				fmt.Println(jwtString)
				if err != nil {
					fmt.Println(err)
				}
			}
		*/
	}

	/*
		Check if expired
	*/

	out, err := uploadrest.Encrypt(GetAuthKeys(dbWebserver).GetAes(), auth.String())
	return fmt.Sprint("?key=", out), nil
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
