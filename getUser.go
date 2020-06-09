package itswizard_jwt

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/itslearninggermany/itswizard_jwt"
	"github.com/itslearninggermany/itszwizard_objects"
	"github.com/itslearninggermany/uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
)

func GetUser(r *http.Request, dbWebserver *gorm.DB) (user itszwizard_objects.SessionUser, err error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return user, err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(auth.IDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(GetAuthKeys(dbWebserver).GetKey()), nil
	})
	if err != nil {
		return user, err
	}

	user = itszwizard_objects.SessionUser{
		Username:            claims["Username"].(string),
		UserID:              uint(claims["UserID"].(float64)),
		FirstAuthentication: claims["FirstAuthentication"].(bool),
		Authenticated:       claims["Authenticated"].(bool),
		TwoFac:              claims["TwoFac"].(bool),
		Firstname:           claims["Firstname"].(string),
		Lastname:            claims["Lastname"].(string),
		Mobile:              claims["Mobile"].(string),
		IpAddress:           fmt.Sprint(claims["IP"]),
		Institution:         claims["Institution"].(string),
		School:              claims["School"].(string),
		Email:               claims["Email"].(string),
		Information:         claims["Information"].(string),
		Admin:               claims["Admin"].(bool),
		OrganisationID:      uint(claims["OrganisationID"].(float64)),
		InstitutionID:       uint(claims["InstitutionID"].(float64)),
	}

	return

}

func GetUserRest(r *http.Request, dbWebserver *gorm.DB) (user itszwizard_objects.SessionUser, err error) {
	tmp, err := uploadrest.Decrypt(itswizard_jwt.GetAuthKeys(dbWebserver).GetAes(), r.Header.Get("Authorization"))
	var auth itswizard_jwt.Authentication
	err = json.Unmarshal([]byte(tmp), &auth)
	if err != nil {
		return user, err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(auth.IDToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(itswizard_jwt.GetAuthKeys(dbWebserver).GetKey()), nil
	})

	if err != nil {
		return user, err
	}

	user = itszwizard_objects.SessionUser{
		Username:            claims["Username"].(string),
		UserID:              uint(claims["UserID"].(float64)),
		FirstAuthentication: claims["FirstAuthentication"].(bool),
		Authenticated:       claims["Authenticated"].(bool),
		TwoFac:              claims["TwoFac"].(bool),
		Firstname:           claims["Firstname"].(string),
		Lastname:            claims["Lastname"].(string),
		Mobile:              claims["Mobile"].(string),
		IpAddress:           fmt.Sprint(claims["IP"]),
		Institution:         claims["Institution"].(string),
		School:              claims["School"].(string),
		Email:               claims["Email"].(string),
		Information:         claims["Information"].(string),
		Admin:               claims["Admin"].(bool),
		OrganisationID:      uint(claims["OrganisationID"].(float64)),
		InstitutionID:       uint(claims["InstitutionID"].(float64)),
	}
	return user, err
}
