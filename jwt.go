package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"gopkg.in/square/go-jose.v2"
	"strconv"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

func (h JWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// if the request path is any of the configured paths, validate JWT
	for _, p := range h.Rules {
		if !httpserver.Path(r.URL.Path).Matches(p.Path) {
			continue
		}

		// Path matches, look for unvalidated token
		uToken, err := ExtractToken(r)
		if err != nil {
			return http.StatusUnauthorized, nil
		}

		// Validate token
		claims, err := ValidateToken(uToken, &p.Keys)
		if err != nil {
			return http.StatusUnauthorized, nil
		}

		// If token contains rules with allow or deny, evaluate
		if len(p.AccessRules) > 0 {
			var isAuthorized []bool
			for _, rule := range p.AccessRules {
				switch rule.Authorize {
				case ALLOW:
					isAuthorized = append(isAuthorized, (*claims)[rule.Claim] == rule.Value)
				case DENY:
					isAuthorized = append(isAuthorized, (*claims)[rule.Claim] != rule.Value)
				default:
					return http.StatusUnauthorized, fmt.Errorf("unknown rule type")
				}
			}
			// test all flags, if any are true then ok to pass
			ok := false
			for _, result := range isAuthorized {
				if result {
					ok = true
					break
				}
			}
			if !ok {
				return http.StatusUnauthorized, nil
			}
		}

		// set claims as separate headers for downstream to consume
		for key, value := range *claims {
			r.Header.Set(strings.Join([]string{"Token-Claim-", SanitizeHeaderName(key)}, ""), toString(value))
		}

		return h.Next.ServeHTTP(w, r)
	}
	// pass request if no paths protected with JWT
	return h.Next.ServeHTTP(w, r)
}

func SanitizeHeaderName(name string) string {
	return strings.Replace(name, ":", "-", -1)
}

// ExtractToken will find a JWT token passed one of three ways: (1) as the Authorization
// header in the form `Bearer <JWT Token>`; (2) as a cookie named `jwt_token`; (3) as
// a URL query paramter of the form https://example.com?token=<JWT token>
func ExtractToken(r *http.Request) (string, error) {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], nil
	}

	jwtCookie, err := r.Cookie("jwt_token")
	if err == nil {
		return jwtCookie.Value, nil
	}

	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, nil
	}

	return "", fmt.Errorf("no token found")
}

// ValidateToken will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func ValidateToken(uToken string, keys *jose.JSONWebKeySet) (*map[string]interface{}, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}

	if jws, err := jwt.ParseSigned(uToken); err == nil  {
		// let's validate using the first signature only
		if jws.Headers[0].KeyID == "" {
			return nil, fmt.Errorf("No key id in signature header.")
		}
		if key, err := lookupJsonWebKey(jws.Headers[0].KeyID, keys); err == nil {
			claims := jwt.Claims{}
			allClaims := new(map[string]interface{})
			if err := jws.Claims(key, &claims, allClaims ); err == nil {
				if err := claims.Validate(jwt.Expected{Time:time.Now()}); err == nil {
					return allClaims, nil
				} else {
					return nil, err
				}
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

func lookupJsonWebKey(kid string, keys *jose.JSONWebKeySet ) (*jose.JSONWebKey, error) {
	for _, key := range keys.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("Unable to find a key for id:%s", kid)
}

func toString(value interface{}) string {
	switch value.(type) {
	case string:
		return value.(string)
	case int64:
		return strconv.FormatInt(value.(int64), 10)
	case bool:
		return strconv.FormatBool(value.(bool))
	case int32:
		return strconv.FormatInt(int64(value.(int32)), 10)
	case float32:
		return strconv.FormatFloat(float64(value.(float32)), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(value.(float64), 'f', -1, 64)
	default:
		return ""
	}
}