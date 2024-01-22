package gTokenVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type certs struct {
	Keys []keys `json:"keys"`
}

type keys struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"Kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// TokenInfo is the struct that contains the information of the token
type TokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	AtHash        string `json:"at_hash"`
	Aud           string `json:"aud"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Local         string `json:"locale"`
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// Verify verifies the token and returns the token info if the token is valid.
// Otherwise, it returns nil.
func Verify(authToken string, aud string) *TokenInfo {
	return verifyGoogleIDToken(authToken, getCerts(getCertsFromURL()), aud)
}

// VerifyByDomain verifies the token and checks if the user in the JWT is from the specified domain.
// Otherwise, it returns nil.
func VerifyByDomain(authToken string, aud string, domain string) *TokenInfo {
	tokeninfo := verifyGoogleIDToken(authToken, getCerts(getCertsFromURL()), aud)
	if tokeninfo == nil {
		return nil
	}

	if !validateDomain(tokeninfo.Email, domain) {
		err := errors.New("token not valid, domain doesn't match")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return nil
	}
	return tokeninfo
}

func verifyGoogleIDToken(authToken string, certs *certs, aud string) *TokenInfo {
	header, payload, signature, messageToSign := divideAuthToken(authToken)

	tokeninfo := getTokenInfo(payload)
	var niltokeninfo *TokenInfo
	if aud != tokeninfo.Aud {
		err := errors.New("token is not valid, Audience from token and certificate don't match")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	if (tokeninfo.Iss != "accounts.google.com") && (tokeninfo.Iss != "https://accounts.google.com") {
		err := errors.New("token is not valid, ISS from token and certificate don't match")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	if !checkTime(tokeninfo) {
		err := errors.New("token is not valid, Token is expired")
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}

	key, err := choiceKeyByKeyID(certs.Keys, getAuthTokenKeyID(header))
	if err != nil {
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	pKey := rsa.PublicKey{N: byteToInt(urlsafeB64decode(key.N)), E: btrToInt(byteToBtr(urlsafeB64decode(key.E)))}
	err = rsa.VerifyPKCS1v15(&pKey, crypto.SHA256, messageToSign, signature)
	if err != nil {
		fmt.Printf("Error verifying key %s\n", err.Error())
		return niltokeninfo
	}
	return tokeninfo
}

func getTokenInfo(bt []byte) *TokenInfo {
	var a *TokenInfo
	err := json.Unmarshal(bt, &a)
	if err != nil {
		log.Printf("token unmarshall error: %s", err.Error())
	}
	return a
}

func checkTime(tokeninfo *TokenInfo) bool {
	if (time.Now().Unix() < tokeninfo.Iat) || (time.Now().Unix() > tokeninfo.Exp) {
		return false
	}
	return true
}

func getCertsFromURL() []byte {
	res, _ := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	certs, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return certs
}

func getCerts(bt []byte) *certs {
	var certs *certs
	err := json.Unmarshal(bt, &certs)
	if err != nil {
		log.Printf("certs unmarshall error: %s", err.Error())
	}
	return certs
}

func urlsafeB64decode(str string) []byte {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, _ := base64.URLEncoding.DecodeString(str)
	return bt
}

func choiceKeyByKeyID(a []keys, tknkId string) (keys, error) {
	if len(a) > 0 {
		for _, key := range a {
			if key.Kid == tknkId {
				return key, nil
			}
		}
	}

	err := errors.New("token is not valid. There is no keyId or certificate doesn't match")
	var b keys
	return b, err
}

func getAuthTokenKeyID(bt []byte) string {
	var a keys
	err := json.Unmarshal(bt, &a)
	if err != nil {
		log.Printf("authToken unmarshall error: %s", err.Error())
		return ""
	}
	return a.Kid
}

func divideAuthToken(str string) ([]byte, []byte, []byte, []byte) {
	args := strings.Split(str, ".")
	return urlsafeB64decode(args[0]), urlsafeB64decode(args[1]), urlsafeB64decode(args[2]), calcSum(args[0] + "." + args[1])
}

func byteToBtr(bt0 []byte) *bytes.Reader {
	var bt1 []byte
	if len(bt0) < 8 {
		bt1 = make([]byte, 8-len(bt0), 8)
		bt1 = append(bt1, bt0...)
	} else {
		bt1 = bt0
	}
	return bytes.NewReader(bt1)
}

func calcSum(str string) []byte {
	a := sha256.New()
	a.Write([]byte(str))
	return a.Sum(nil)
}

func btrToInt(a io.Reader) int {
	var e uint64
	binary.Read(a, binary.BigEndian, &e)
	return int(e)
}

func byteToInt(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}

func validateDomain(email string, domain string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	if !validateFormat(email) {
		return false
	}
	emailDomain := parts[1]

	return emailDomain == domain
}

func validateFormat(email string) bool {
	regex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return regex.MatchString(email)
}
