package jwt

import (
	"net/http"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sgaide/caddy"
	"github.com/sgaide/caddy/caddyhttp/httpserver"
	"gopkg.in/square/go-jose.v2"
)

func TestCaddyJwtConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CaddyJWT Config Suite")
}

var EmptyNext = httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
})

var _ = Describe("JWTAuth Config", func() {
	Describe("Parse the jwt config block", func() {

		It("returns an appropriate middleware handler", func() {
			c := caddy.NewTestController("http", `jwt /from`)
			err := Setup(c)
			Expect(err).To(BeNil())
		})

		It("parses simple and complex blocks", func() {
			tests := []struct {
				input     string
				shouldErr bool
				expect    []Rule
			}{
				{"jwt /test", false, []Rule{{"/test", nil, jose.JSONWebKeySet{}}}},
				{"jwt {\npath /test\n}", false, []Rule{{"/test", nil, jose.JSONWebKeySet{}}}},
				{`jwt {
					path /test
					allow user test
				}`, false, []Rule{{"/test", []AccessRule{{ALLOW, "user", "test"}}, jose.JSONWebKeySet{}}}},
				{`jwt /test {
					allow user test
				}`, true, nil},
				{`jwt {
					path /test
					deny role member
					allow user test
				}`, false, []Rule{{"/test", []AccessRule{{DENY, "role", "member"}, {ALLOW, "user", "test"}}, jose.JSONWebKeySet{}}}},
				{`jwt {
					deny role member
				}`, true, nil},
				{`jwt /path1
				jwt /path2`, false, []Rule{{"/path1", nil, jose.JSONWebKeySet{}}, {"/path2", nil, jose.JSONWebKeySet{}}}},
				{`jwt {
					path /path1
					path /path2
				}`, true, nil},
			}
			for _, test := range tests {
				c := caddy.NewTestController("http", test.input)
				actual, err := parse(c)
				if !test.shouldErr {
					Expect(err).To(BeNil())
				} else {
					Expect(err).To(HaveOccurred())
				}
				for idx, rule := range test.expect {
					actualRule := actual[idx]
					Expect(rule.Path).To(Equal(actualRule.Path))
					Expect(rule.AccessRules).To(Equal(actualRule.AccessRules))
				}

			}
		})

	})
})
