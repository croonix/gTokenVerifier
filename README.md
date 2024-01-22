# gTokenVerifier

This module seeks to have a similarity to that found in [Verify the Google ID token on your server side](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token) for other languages. It validates if the generated JWT corresponds to Google and also provides the possibility to validate if the user who issued the token is or is not from a specific domain.

## Uso

Here is a basic example of how to use it:

```go
package main

import (
	"fmt"

	gTokenVerifier "github.com/croonix/gTokenVerifier"
)

var (
    token := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
    aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	domain = "dev.intelligencepartner.com"
)

func main() {
	tokenInfo := gTokenVerifier.Verify(token, aud)
	if tokenInfo != nil {
		fmt.Println(tokenInfo)
	}

	tokenInfo = gTokenVerifier.VerifyByDomain(token, aud, domain)
	if tokenInfo != nil {
		fmt.Println(tokenInfo)
	}
}

```