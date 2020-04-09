package itswizard_jwt

import (
	"github.com/jinzhu/gorm"
)

func DidUserLogOut(username string, dbWebserver *gorm.DB) bool {

	var x JwtSession
	if dbWebserver.Where("user_name = ?", username).First(&x).RecordNotFound() {
		return true
	} else {
		return false
	}
}
