package itswizard_jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/itswizard_basic"
	"github.com/jinzhu/gorm"
	"net/http"
	"strings"
	"time"
)

type JwtSession struct {
	gorm.Model
	UserName string `gorm:"unique"`
	Token    string `gorm:"type:MEDIUMTEXT"`
}

func CreateToken(r *http.Request, username string, dbUser *gorm.DB, dbWebserver *gorm.DB) (authJson string, jwtToken string, err error) {

	var user itswizard_basic.DbItswizardUser15
	err = dbUser.Where("username = ?", username).First(&user).Error
	if err != nil {
		return "", "", err
	}

	var orga itswizard_basic.DbOrganisation15
	err = dbUser.Where("id = ?", user.OrganisationID).First(&orga).Error
	if err != nil {
		return "", "", err
	}

	var inst itswizard_basic.DbInstitution15
	err = dbUser.Where("id = ?", orga.InstitutionID).First(&inst).Error
	if err != nil {
		return "", "", err
	}

	ip := strings.Split(r.RemoteAddr, ":")
	fmt.Println(ip)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username":            username,
		"UserID":              user.Model.ID,
		"FirstAuthentication": true,
		"Authenticated":       true,
		"TwoFac":              user.TwoFac,
		"Firstname":           user.Firstname,
		"Lastname":            user.Lastname,
		"Mobile":              user.Tel,
		"IpAddress":           fmt.Sprint(ip[0]),
		"Institution":         inst.Name,
		"School":              orga.Name,
		"Email":               user.Email,
		"Information":         "--",
		"Admin":               false,
		"OrganisationID":      orga.ID,
		"InstitutionID":       inst.ID,
		"exp":                 time.Now().Add(time.Minute * time.Duration(60)).Unix(),
		"iat":                 time.Now().Unix(),
	})

	tokenString, err := token.SignedString(GetAuthKeys(dbWebserver).GetKey())
	if err != nil {
		return "", "", err
	}

	refreshToken := createRefreshToken(username)
	err = refreshToken.StoreInDatatbae(dbWebserver)
	if err != nil {
		return "", "", err
	}

	//Store And logout
	var jwtSession JwtSession
	if dbWebserver.Where("user_name = ?", username).First(&jwtSession).RecordNotFound() {
		jwtSession.UserName = username
		jwtSession.Token = tokenString
	} else {
		jwtSession.Token = tokenString
	}

	err = dbWebserver.Save(&jwtSession).Error
	if err != nil {
		return "", "", err
	}
	//
	auth := CreateNewAuthUrl("123", tokenString, refreshToken.String(), dbWebserver)

	return auth, tokenString, err
}
