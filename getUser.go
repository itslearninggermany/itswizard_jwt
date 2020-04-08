package itswizard_jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/itszwizard_objects"
	"github.com/jinzhu/gorm"
	"net/http"
)

func GetUser(r *http.Request, dbWebserver *gorm.DB) (user itszwizard_objects.SessionUser, err error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return user, err
	}
	fmt.Println(auth.IDToken)

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(auth.IDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(GetAuthKeys(dbWebserver).GetKey()), nil
	})
	if err != nil {
		return user, err
	}

	user = itszwizard_objects.SessionUser{
		Username: claims["Username"].(string),
		//		UserID:              uint(claims["UserID"].(int)),
		FirstAuthentication: claims["FirstAuthentication"].(bool),
		Authenticated:       claims["Authenticated"].(bool),
		TwoFac:              claims["TwoFac"].(bool),
		Firstname:           claims["Firstname"].(string),
		Lastname:            claims["Lastname"].(string),
		Mobile:              claims["Mobile"].(string),
		IpAddress:           claims["IPAddress"].(string),
		Institution:         claims["Institution"].(string),
		School:              claims["School"].(string),
		Email:               claims["Email"].(string),
		Information:         claims["Information"].(string),
		Admin:               claims["Admin"].(bool),
		OrganisationID:      claims["OrganisationID"].(uint),
		InstitutionID:       claims["InstitutionID"].(uint),
	}

	return

}
