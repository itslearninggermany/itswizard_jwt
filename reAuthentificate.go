package itswizard_jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
	"time"
)

func ReAuthentificate(r *http.Request, dbWebserver *gorm.DB) (string, error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(auth.IDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(GetAuthKeys(dbWebserver).GetKey()), nil
	})
	if err != nil {
		return "", err
	}

	exp := time.Unix(int64(claims["exp"].(float64)), 0)

	// Is the token valid
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

		/*
			Check if expired
		*/

		out, err := uploadrest.Encrypt(GetAuthKeys(dbWebserver).GetAes(), auth.String())
		return fmt.Sprint("?key=", out), err
	} else {
		//The Token is valid
		res := r.URL.Query()["key"]
		if len(res) == 0 {
			return "", errors.New("Problem with Toke in URL")
		}
		return fmt.Sprint("?key=", res), nil
	}
}
