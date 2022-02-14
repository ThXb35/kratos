package saml

import (
	"bytes"
	"context"
	"net/url"

	"github.com/crewjam/saml/samlsp"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/jsonx"
	"github.com/pkg/errors"
)

type ProviderSAML struct {
	idpMetadataUrl *url.URL
	idpSsoUrl      *url.URL
	config         *Configuration
}

func NewProviderSAML(
	idpMetadataUrl *url.URL,
	idpSsoUrl *url.URL,
	config *Configuration,
) *ProviderSAML {
	return &ProviderSAML{
		idpMetadataUrl: idpMetadataUrl,
		idpSsoUrl:      idpSsoUrl,
		config:         config,
	}
}

func (d *ProviderSAML) Claims(ctx context.Context, config *config.Config, SAMLAttribute samlsp.Attributes) (*Claims, error) {

	var c ConfigurationCollection

	conf := config.SelfServiceStrategy("saml").Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		return nil, errors.Wrapf(err, "Unable to decode config %v", string(conf))
	}

	claims := &Claims{
		Issuer:        "saml",
		Subject:       SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["id"]),
		Name:          SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["firstname"]),
		LastName:      SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["lastname"]),
		Nickname:      SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["nickname"]),
		Gender:        SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["gender"]),
		Birthdate:     SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["birthdate"]),
		Picture:       SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["picture"]),
		Email:         SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["email"]),
		PhoneNumber:   SAMLAttribute.Get(c.SAMLProviders[len(c.SAMLProviders)-1].AttributesMap["phone_number"]),
		EmailVerified: true,
	}

	return claims, nil
}

func (d *ProviderSAML) Config() *Configuration {
	return d.config
}
