package itswizard_jwt

import (
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

type RefreshToken struct {
	gorm.Model
	refreshToken string
	username string
}


func createRefreshToken (username string) *RefreshToken {
	re := new(RefreshToken)
	u1 := uuid.Must(uuid.NewV4())
	re.refreshToken = u1.String()
	re.username = username
	return re
}


func (p *RefreshToken) String () string {
	return p.refreshToken
}

func (p *RefreshToken) StoreInDatatbae (dbWebserver *gorm.DB) error{
	return dbWebserver.Save(&p).Error
}

