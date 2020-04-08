package itswizard_jwt

import (
	"github.com/jinzhu/gorm"
	"net/http"
	"strings"
)

//itszwizard_objects.SessionUser
func GetUser(r *http.Request, dbWebserver *gorm.DB) (user string, err error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return user, err
	}
	var payload string
	erg := strings.Split(auth.IDToken, ".")
	if len(erg) != 3 {
		return user, err
	} else {
		payload = erg[1]
	}

	a, err := base64url_decode([]byte(payload))
	if err != nil {
		return
	}

	user = string(a)
	return
}
