//go:build darwin && cgo
// +build darwin,cgo

package commands

import (
	"github.com/AdrianAcala/saml2aws/v2/helper/credentials"
	"github.com/AdrianAcala/saml2aws/v2/helper/osxkeychain"
)

func init() {
	credentials.CurrentHelper = &osxkeychain.Osxkeychain{}
}
