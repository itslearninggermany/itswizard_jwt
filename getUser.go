package itswizard_jwt

import (
	"fmt"
	"github.com/itslearninggermany/itszwizard_objects"
	"github.com/jinzhu/gorm"
	"net/http"
	"strings"
)

func GetUser(r *http.Request, dbWebserver *gorm.DB) (user itszwizard_objects.SessionUser, err error) {
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

	jwtClaims, err := decodePayload(payload)
	fmt.Println(jwtClaims)

	return
}
