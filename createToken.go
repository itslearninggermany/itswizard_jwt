package itswizard_jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/itswizard_basic"
	"github.com/itslearninggermany/itszwizard_objects"
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

func CreateToken(r *http.Request, username string, dbUser *gorm.DB, dbWebserver *gorm.DB) (authString string, sessionUser itszwizard_objects.SessionUser, err error) {

	var user itswizard_basic.DbItswizardUser15
	err = dbUser.Where("username = ?", username).First(&user).Error
	if err != nil {
		fmt.Println(err)
		return "", sessionUser, err
	}

	var orga itswizard_basic.DbOrganisation15
	err = dbUser.Where("id = ?", user.OrganisationID).First(&orga).Error
	if err != nil {
		// TODO HTTP REDIRECT
		fmt.Println(err)
		return "", sessionUser, err
	}

	var inst itswizard_basic.DbInstitution15
	err = dbUser.Where("id = ?", orga.InstitutionID).First(&inst).Error
	if err != nil {
		// TODO HTTP REDIRECT
		fmt.Println(err)
		return "", sessionUser, err
	}

	ip := strings.Split(r.RemoteAddr, ":")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Username":            username,
		"UserID":              user.Model.ID,
		"FirstAuthentication": true,
		"Authenticated":       true,
		"TwoFac":              user.TwoFac,
		"Firstname":           user.Firstname,
		"Lastname":            user.Lastname,
		"Mobile":              user.Tel,
		"IP":                  ip[0],
		"Institution":         inst.Name,
		"School":              orga.Name,
		"Email":               user.Email,
		"Information":         "--",
		"Admin":               user.Admin,
		"OrganisationID":      orga.ID,
		"InstitutionID":       inst.ID,
		"exp":                 time.Now().Add(time.Minute * time.Duration(60)).Unix(),
		"iat":                 time.Now().Unix(),
	})

	sessionUser = itszwizard_objects.SessionUser{
		Username:            username,
		UserID:              user.Model.ID,
		FirstAuthentication: true,
		Authenticated:       true,
		TwoFac:              user.TwoFac,
		Firstname:           user.Firstname,
		Lastname:            user.Lastname,
		Mobile:              user.Tel,
		IpAddress:           ip[0],
		Institution:         inst.Name,
		School:              orga.Name,
		Email:               user.Email,
		Information:         "--",
		Admin:               user.Admin,
		OrganisationID:      orga.ID,
		InstitutionID:       inst.ID,
	}

	tokenString, err := token.SignedString(GetAuthKeys(dbWebserver).GetKey())
	if err != nil {
		// TODO HTTP REDIRECT
		fmt.Println(err)
		return "", sessionUser, err
	}

	refreshToken := createRefreshToken(username)
	err = refreshToken.StoreInDatatbae(dbWebserver)
	if err != nil {
		// TODO HTTP REDIRECT
		fmt.Println(err)
		return "", sessionUser, err
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
		// TODO HTTP REDIRECT
		fmt.Println(err)
		return "", sessionUser, err
	}

	return CreateNewAuthUrl("123", tokenString, refreshToken.String(), dbWebserver), sessionUser, nil
}
