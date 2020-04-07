package itswizard_jwt

import (
	"errors"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"net/http"
	"strings"
	"time"
)

// AuthMiddleware is our middleware to check our token is valid. Returning
// a 401 status to the client if it is not valid.
func AuthMiddlewareJWT(next http.Handler, dbWebserver *gorm.DB) http.Handler {

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return GetAuthKeys(dbWebserver).GetKey(), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		Extractor:     GetJWT,
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

/*
This function get the JWT and checks if the token is expired. When it is expired. A new JWT will be created
*/
func GetJWT(r *http.Request) (jwtString string, err error) {
	res := r.URL.Query()["token"]
	if len(res) == 0 {
		return "", errors.New("no token")
	} else {
		jwtString = res[0]
	}

	err = r.ParseForm()
	if err != nil {
		return "", err
	}

	var payload string
	erg := strings.Split(jwtString, ".")
	if len(erg) != 3 {
		return "", err
	} else {
		payload = erg[1]
	}

	jwtClaims, err := decodePayload(payload)

	//in the cookie
	//	var authJson string

	exp := time.Unix(int64(jwtClaims.Exp), 0)
	if time.Now().Sub(exp) > 0 {

		fmt.Println("Refresh den Cookie")

		if CheckRefreshToken("asdasd") {
			_, jwtString, err = CreateToken("username")
			fmt.Println(jwtString)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	//Neues Ding im Cookie speichern

	return jwtString, err
}

func SetJwt() {

	/*
		Check if JWT is valid
	*/

}

func NewAuth(username string, dbClient *gorm.DB, dbWebserver *gorm.DB) {

	CreateToken(username, dbClient, dbWebserver)
}
