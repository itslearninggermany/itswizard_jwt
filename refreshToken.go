package itswizard_jwt

import (
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"net/http"
	"time"
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

func getRefreshTokenFromDatabase(username string, dbWebserver *gorm.DB) (*RefreshToken, error) {
	var rToken RefreshToken
	err := dbWebserver.Where("username = ?", username).Last(&rToken).Error
	return &rToken, err
}

func (p *RefreshToken) Valid(dbWebserver *gorm.DB) bool {
	// Check if Token is in Database:
	exist := dbWebserver.Where("refresh_token", p.RefreshToken).RecordNotFound()
	if exist {
		if getHoursScinceCreatet(p.CreatedAt) > 0 {
			return false
		} else {
			return true
		}
	} else {
		return false
	}
}

func getHoursScinceCreatet(input time.Time) float64 {
	aus := time.Now().Sub(input)
	return aus.Minutes()
}
