package itswizard_jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
	"time"
)

type JwtClaimsStruct struct {
	Admin               bool   `json:"Admin"`
	Authenticated       bool   `json:"Authenticated"`
	Email               string `json:"Email"`
	FirstAuthentication bool   `json:"FirstAuthentication"`
	Firstname           string `json:"Firstname"`
	Information         string `json:"Information"`
	Institution         string `json:"Institution"`
	InstitutionID       uint   `json:"InstitutionID"`
	IPAddress           string `json:"IpAddress"`
	Lastname            string `json:"Lastname"`
	Mobile              string `json:"Mobile"`
	OrganisationID      uint   `json:"OrganisationID"`
	School              string `json:"School"`
	TwoFac              bool   `json:"TwoFac"`
	UserID              uint   `json:"UserID"`
	Username            string `json:"Username"`
	Exp                 int    `json:"exp"`
	Iat                 int    `json:"iat"`
}

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

/*
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

func decodePayload(input string) (jwtdata JwtClaimsStruct, err error) {
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
*/
