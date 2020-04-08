package itswizard_jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/itswizard_basic"
	"github.com/jinzhu/gorm"
	"time"
)

type JwtSession struct {
	gorm.Model
	UserName string `gorm:"unique"`
	Token    string `gorm:"type:MEDIUMTEXT"`
}

func CreateToken(username string, dbUser *gorm.DB, dbWebserver *gorm.DB) (authJson string, jwtToken string, err error) {

	var user itswizard_basic.DbItswizardUser15
	dbUser.Where("username = ?", username).First(&user)

	role := ""
	if user.Admin {
		role = "admin"
	} else {
		role = "client"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user":           username,
		"firstName":      user.Firstname,
		"lastName":       user.Lastname,
		"Email":          user.Email,
		"OrganisationID": user.OrganisationID,
		"role":           role,
		"exp":            time.Now().Add(time.Minute * time.Duration(60)).Unix(),
		"iat":            time.Now().Unix(),
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
	if dbWebserver.Where("user_name = ?", username).First(&jwtToken).RecordNotFound() {
		jwtSession.UserName = username
		jwtSession.Token = tokenString
	} else {
		jwtSession.Token = tokenString
	}
	dbWebserver.Save(&jwtSession)

	//
	auth := CreateNewAuthUrl("123", tokenString, refreshToken.String(), dbWebserver)

	return auth, tokenString, err
}
