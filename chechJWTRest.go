package itswizard_jwt

import (
	"encoding/json"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
)

func CheckJWTRest(w http.ResponseWriter, r *http.Request, dbwebserver *gorm.DB) error {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return GetAuthKeys(dbwebserver).GetKey(), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		Extractor: func(r *http.Request) (string, error) {
			tmp, err := uploadrest.Decrypt(GetAuthKeys(dbwebserver).GetAes(), r.Header.Get("Authorization"))
			var auth Authentication
			err = json.Unmarshal([]byte(tmp), &auth)
			return auth.IDToken, err
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err string) {
			http.Error(w, err, http.StatusUnauthorized)
		},
	})

	return jwtMiddleware.CheckJWT(w, r)
}
