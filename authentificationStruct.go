package itswizard_jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itslearninggermany/uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
)

type Authentication struct {
	AccessToken  string `json:"AccessToken"`
	ExpiresIn    uint   `json:"ExpiresIn"`
	IDToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
}

func setAuthentification(AccessToken, IDToken, RefreshToken string) *Authentication {
	a := new(Authentication)
	a.ExpiresIn = 3600
	a.AccessToken = AccessToken
	a.IDToken = IDToken
	a.RefreshToken = RefreshToken
	a.TokenType = "Bearer"
	return a
}

func (a *Authentication) String() string {
	out, _ := json.Marshal(a)
	return string(out)
}

func CreateNewAuthUrl(AccessToken, IDToken, RefreshToken string, dbWebserver *gorm.DB) string {
	authentification := setAuthentification(AccessToken, IDToken, RefreshToken)
	out, err := uploadrest.Encrypt(GetAuthKeys(dbWebserver).GetAes(), authentification.String())
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprint("?key=", out)
}

func DecodeAuthentification(r *http.Request, dbWebserver *gorm.DB) (auth Authentication, err error) {
	res := r.URL.Query()["key"]
	if len(res) == 0 {
		return auth, errors.New("no token")
	} else {
		tmp, err := uploadrest.Decrypt(GetAuthKeys(dbWebserver).GetAes(), res[0])
		if err != nil {
			return auth, err
		}
		err = json.Unmarshal([]byte(tmp), auth)
	}
	return
}
