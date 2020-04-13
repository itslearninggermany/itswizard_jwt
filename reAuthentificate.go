package itswizard_jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"net/http"
	"net/url"
	"time"
)

func ReAuthentificate(r *http.Request, dbWebserver *gorm.DB, dbUser *gorm.DB) (authToken string, err error) {
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
		rtoken := GetRefreshTokenFromDatatabse(auth.RefreshToken, dbWebserver)

		if rtoken.Valid(claims["Username"].(string)) {
			authtoken, _, err := CreateToken(r, claims["Username"].(string), dbUser, dbWebserver)
			if err != nil {
				return "", err
			}
			return authtoken, nil
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
		jwttoken, err := url.PathUnescape(res[0])
		if err != nil {
			fmt.Println(err)
			return "", err
		}

		return jwttoken, nil
	}
}
