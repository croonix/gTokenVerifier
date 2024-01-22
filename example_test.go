package gTokenVerifier_test

import (
	"fmt"

	"github.com/croonix/gTokenVerifier"
)

func ExampleVerifyByDomain() {
	var (
		authTokenTest = ""
		audTest       = ""
		audDomainTest = ""
	)

	tokenInfo := gTokenVerifier.VerifyByDomain(authTokenTest, audTest, audDomainTest)

	if tokenInfo != nil {
		fmt.Println(tokenInfo)
	}
}

func ExampleVerify() {
	var (
		authTokenTest = ""
		audTest       = ""
	)

	tokenInfo := gTokenVerifier.Verify(authTokenTest, audTest)

	if tokenInfo != nil {
		fmt.Println(tokenInfo)
	}
}
