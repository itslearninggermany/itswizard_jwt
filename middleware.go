package itswizard_jwt

import (
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"net/http"
)

// AuthMiddleware is our middleware to check our token is valid. Returning
// a 401 status to the client if it is not valid.
func AuthMiddlewareJWT(next http.Handler, dbWebserver *gorm.DB) http.Handler {

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return GetAuthKeys(dbWebserver).GetKey(), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		Extractor: func(r *http.Request) (string, error) {
			auth, err := DecodeAuthentification(r, dbWebserver)
			if err != nil {
				return "", err
			}
			return auth.IDToken, err
		},
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		err := jwtMiddleware.CheckJWT(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		next.ServeHTTP(w, r)
	})

}
