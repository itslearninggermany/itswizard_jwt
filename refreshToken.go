package itswizard_jwt

import (
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"net/http"
)

type RefreshToken struct {
	gorm.Model
	RefreshToken string `gorm:"unique"`
	Username     string
}

func createRefreshToken(username string) *RefreshToken {
	re := new(RefreshToken)
	u1 := uuid.Must(uuid.NewV4())
	re.RefreshToken = u1.String()
	re.Username = username
	return re
}

func (p *RefreshToken) String() string {
	return p.RefreshToken
}

func (p *RefreshToken) StoreInDatatbae(dbWebserver *gorm.DB) error {
	return dbWebserver.Save(&p).Error
}

func Authentificate(r *http.Request) string {

	return ""
}
