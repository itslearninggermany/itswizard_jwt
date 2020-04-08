package itswizard_jwt

import (
	"fmt"
	"github.com/itslearninggermany/itszwizard_objects"
	"github.com/jinzhu/gorm"
	"net/http"
)

func GetUser(r *http.Request, dbWebserver *gorm.DB) (user itszwizard_objects.SessionUser, err error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return user, err
	}

	b, err := base64url_decode([]byte(auth.IDToken))
	fmt.Println(err)
	fmt.Println(string(b))
	return user, err
}
