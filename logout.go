package itswizard_jwt

import (
	"fmt"
	"github.com/jinzhu/gorm"
	"net/http"
)

func Logout(r *http.Request, dbWebserver *gorm.DB) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}

	err = dbWebserver.Delete("refresh_token = ?", auth.RefreshToken).Error
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}

	err = dbWebserver.Where("token = ?", auth.IDToken).Error
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}
}
