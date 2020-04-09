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

	var rtoken RefreshToken
	err = dbWebserver.Where("refresh_token = ?", auth.RefreshToken).First(&rtoken).Error
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}
	err = dbWebserver.Delete(&rtoken).Error
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}

	var jwtSession JwtSession
	err = dbWebserver.Where("token = ?", auth.IDToken).First(&jwtSession).Error
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}
	err = dbWebserver.Delete(&jwtSession).Error
	if err != nil {
		// TODO: HHTP Redirect
		fmt.Println(err)
		return
	}
}
