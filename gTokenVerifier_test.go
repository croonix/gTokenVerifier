package gTokenVerifier

import (
	"testing"
)

var (
	// authTokenTest = os.Getenv("AUTH_TOKEN")
	// audTest       = os.Getenv("AUD")
	// audDomainTest = os.Getenv("DOMAIN")

	authTokenTest = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ4YTYzYmM0NzY3Zjg1NTBhNTMyZGM2MzBjZjdlYjQ5ZmYzOTdlN2MiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3OTUxMDg5NDk4MTMtdnAxcnQyMTBjNjV1aXZpdDI0ajcxdDkzdDUyOXRkZWguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3OTUxMDg5NDk4MTMtdnAxcnQyMTBjNjV1aXZpdDI0ajcxdDkzdDUyOXRkZWguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDY3ODY0NzUxNjc2MDQ2Mzg1ODkiLCJoZCI6ImRldi5pbnRlbGxpZ2VuY2VwYXJ0bmVyLmNvbSIsImVtYWlsIjoicm9kb2xmby5jYXN0ZWxvQGRldi5pbnRlbGxpZ2VuY2VwYXJ0bmVyLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE3MDU5NjIwODUsIm5hbWUiOiJSb2RvbGZvIENhc3RlbG8iLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSVhiazhOVzBWZWR6NDJNV1NwWjBKcHdfNUtoLWd3ei0zZTBUUFhjMGRlPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IlJvZG9sZm8iLCJmYW1pbHlfbmFtZSI6IkNhc3RlbG8iLCJsb2NhbGUiOiJlbiIsImlhdCI6MTcwNTk2MjM4NSwiZXhwIjoxNzA1OTY1OTg1LCJqdGkiOiJiYjJmZGUxNDlkNmRkMzY3YzBjODU4NWUzOWE4OGJjYjVhNDVlZTNiIn0.Y7mWQGsPjHTOApSLjf_SbPXNKrddTD_XJmeBc_pQITD25o8bUQB4C6BUpi2SEePXy9_XlSZ_ltZFtMeCF2DJdpKpERjAdLKWb3nF1_Nr8eZtBWMQFHtRycsvIE3p6VxJwtYV9wR10KvAhvq_wh9xp-AWWndAhE8v_6YUXTmqHxMPiVQ4NbZb4ukCVl7ffW865akZ2jTe56JhsPQdNT2EUL3faWLpMdUjkZIkAANP902VQIQ3dqPgu6KPYbScTV7wh5y5XopfO_JCPxAsV5errqGHm56FRJaEBCCcithAVNeEg4X3kkbI9f19UGiE6NAcFvtvWROAliitk_y3nF3_fg"
	audTest       = "795108949813-vp1rt210c65uivit24j71t93t529tdeh.apps.googleusercontent.com"
	audDomainTest = "dev.intelligencepartner.com"
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
