package itswizard_jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"net/http"
	"time"
)

func ReAuthentificate(r *http.Request, dbWebserver *gorm.DB, dbUser *gorm.DB) (string, error) {
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

	fmt.Println("exp: ", exp)

	// Is the token valid
	if time.Now().Sub(exp) > 0 {
		// Not valid

		fmt.Println("Refresh den Cookie")

		rtoken := GetRefreshTokenFromDatatabse(auth.RefreshToken, dbWebserver)

		if rtoken.Valid(claims["Username"].(string)) {

			authJson, _, err := CreateToken(r, claims["Username"].(string), dbUser, dbWebserver)
			if err != nil {
				return "", errors.New("Refresh-Token valid. Can't create JWT-Token!")
			}
			return authJson, err

		} else {
			return "", errors.New("Refresh-Token and JWT-Token ist not valid!")
		}
	} else {
		//Valid
		//The Token is valid
		res := r.URL.Query()["key"]
		if len(res) == 0 {
			return "", errors.New("Problem with Toke in URL")
		}
		return fmt.Sprint("?key=", res[0]), nil
	}
}
