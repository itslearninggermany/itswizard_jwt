package itswizard_jwt

import (
	"github.com/itslearninggermany/itszwizard_objects"
	"github.com/jinzhu/gorm"
	"net/http"
)

func GetUser(r *http.Request, dbWebserver *gorm.DB) (user itszwizard_objects.SessionUser, err error) {
	auth, err := DecodeAuthentification(r, dbWebserver)
	if err != nil {
		return user, err
	}

	jwtData, err := decodePayload(auth.IDToken)
	if err != nil {
		return user, err
	}

	user = itszwizard_objects.SessionUser{
		Username:            jwtData.Username,
		UserID:              jwtData.UserID,
		FirstAuthentication: jwtData.FirstAuthentication,
		Authenticated:       jwtData.Authenticated,
		TwoFac:              jwtData.TwoFac,
		Firstname:           jwtData.Firstname,
		Lastname:            jwtData.Lastname,
		Mobile:              jwtData.Mobile,
		IpAddress:           jwtData.IPAddress,
		Institution:         jwtData.Institution,
		School:              jwtData.School,
		Email:               jwtData.Email,
		Information:         jwtData.Information,
		Admin:               jwtData.Admin,
		OrganisationID:      jwtData.OrganisationID,
		InstitutionID:       jwtData.InstitutionID,
	}
	return
}
