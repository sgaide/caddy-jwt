package jwt

import (
	"net/http"
	"strings"
	"testing"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
)

func TestCaddyJwt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CaddyJWT Suite")
}


var _ = Describe("JWTAuth", func() {


	Describe("Find tokens in the request", func() {

		It("should return the token if set in the Auhorization header", func() {
			req, _ := http.NewRequest("GET", "/testing", nil)
			req.Header.Set("Authorization", strings.Join([]string{"Bearer", validToken}, " "))
			token, err := ExtractToken(req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

		It("should return the token if set in a cookie", func() {
			req, _ := http.NewRequest("GET", "/testing", nil)
			req.AddCookie(&http.Cookie{Name: "jwt_token", Value: validToken})
			token, err := ExtractToken(req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

		It("should return the token if set as query parameter", func() {
			url := strings.Join([]string{"/testing?token=", validToken}, "")
			req, _ := http.NewRequest("GET", url, nil)
			token, err := ExtractToken(req)
			Expect(err).To(BeNil())
			Expect(token).To(Equal(validToken))
		})

	})


})
