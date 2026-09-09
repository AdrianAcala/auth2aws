package commands

import (
	"github.com/AdrianAcala/saml2aws/v2/helper/credentials"
	"github.com/AdrianAcala/saml2aws/v2/helper/wincred"
)

func init() {
	credentials.CurrentHelper = &wincred.Wincred{}
}
