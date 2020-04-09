package itswizard_jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"net/http"
	"time"
)

func ReAuthentificate(r *http.Request, dbWebserver *gorm.DB, dbUser *gorm.DB) string {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return ""
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(auth.IDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(GetAuthKeys(dbWebserver).GetKey()), nil
	})
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return ""
	}

	exp := time.Unix(int64(claims["exp"].(float64)), 0)

	// Is the token valid
	if time.Now().Sub(exp) > 0 {
		// Not valid

		fmt.Println("Refresh den Cookie")

		rtoken := GetRefreshTokenFromDatatabse(auth.RefreshToken, dbWebserver)

		if rtoken.Valid(claims["Username"].(string)) {
			return CreateToken(r, claims["Username"].(string), dbUser, dbWebserver)
		} else {
			// TODO: HHTP Redirect
			fmt.Println(errors.New("Refresh-Token and JWT-Token ist not valid!"))
			return ""
		}
	} else {
		//Valid
		//The Token is valid
		res := r.URL.Query()["key"]
		if len(res) == 0 {
			// TODO: HHTP Redirect
			fmt.Println(errors.New("Problem with Toke in URL"))
			return ""
		}
		return fmt.Sprint("?key=", res[0])
	}
}
