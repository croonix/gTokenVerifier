package gTokenVerifier

import (
	"os"
	"testing"
)

var (
	authTokenTest = os.Getenv("AUTH_TOKEN")
	audTest       = os.Getenv("AUD")
	audDomainTest = os.Getenv("DOMAIN")
)

func TestCheckToken(t *testing.T) {
	actual := Verify(authTokenTest, audTest)
	var token *TokenInfo
	expected := token
	if actual == expected {
		t.Errorf("got %v\nwant %v", actual, expected)
	}
}

func TestCheckTokenDomain(t *testing.T) {
	actual := VerifyByDomain(authTokenTest, audTest, audDomainTest)
	var token *TokenInfo
	expected := token
	if actual == expected {
		t.Errorf("got %v\nwant %v", actual, expected)
	}
}
