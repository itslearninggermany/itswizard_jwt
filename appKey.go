package itswizard_jwt

import "github.com/jinzhu/gorm"

type AuthKeys struct {
	gorm.Model
	Key string
	Aes string
}


func GetAuthKeys (dbWebserver *gorm.DB) AuthKeys {
	var auth AuthKeys
	dbWebserver.Last(&auth)
	return auth
}

func (a *AuthKeys) GetKey () []byte {
	return []byte(a.Key)
}

func (a *AuthKeys) GetAes () []byte {
	return []byte(a.Aes)
}