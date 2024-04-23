package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

const (
	// Replace with your actual RSA public key
	rsaPublicKeyPEM = `-----BEGIN CERTIFICATE-----
	MIIDHTCCAgWgAwIBAgIJM4yoDkRJZvCMMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
	BAMTIWRldi1qbTB0c3dqNDdxejJubGF4LnVzLmF1dGgwLmNvbTAeFw0yNDAyMjkw
	OTA5NDFaFw0zNzExMDcwOTA5NDFaMCwxKjAoBgNVBAMTIWRldi1qbTB0c3dqNDdx
	ejJubGF4LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
	ggEBALlQvrrL1k/YCMmYxXfox8TYhSxq1HGNAIKoUpqXIm1WiK+DRI13LVxqx3fP
	tUgWhplSsuMwBvMVC2JAqWUHwLg9qGo770KbVkr5M1fs6fN1Oy+eLXcaGtmGOx3N
	zgQq42xPscZ0dfUsvTM4tQw2i0el5fkhgowjd4UxUn0qh+fg+Lbf3VSryIZY5hjh
	CYg+ZexdUrBCF0MTWAPeZ01pxWeWnwJvJQVe9wohY842CyX9w90PU/5kEPheNWP1
	iKGs7ablpD+hx7tFPZcaBCg/NHkTpCepH88xP34ZwifuGO57pYNgAe1+flulfMLp
	q4HkavHwbeoOaLhjlpAKmQaoXl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
	BgNVHQ4EFgQUwmm4qUnwFBtI+r7AgG4szyYNA+IwDgYDVR0PAQH/BAQDAgKEMA0G
	CSqGSIb3DQEBCwUAA4IBAQA76ZdG0fmdHq5LfXObMBiuggUoK6vqcPWnp9t4pyd5
	J6RNgB1h/driTC7YzATKvblHyzssrPqs3LPnwC3rqbT6zW7OMni33Cux3qDjG402
	b1DVupPUn+z8emN3m0KgDmC2NxDDFFq+1b35u2C0eOvwM/5+6pPf55VPxdAA2Oyi
	JZf6081Yk3nKXY+Wbcy1YC7Z1QaF3EFaHrmygUHQJJ9nBWtzUPOl6MCFJFW2wa/i
	8RQCJ2wMLPIYuVvFbpGbuZSIasH2q81rkBvTvtbgs+nREyJk+KR2QnlhBRO6PRkm
	Zt2+R0yZTgaYVsxnm+IUUYT1uM7LRPvxW8EMM5lWGFhm
	-----END CERTIFICATE-----`

	Auth0Audience = "weyssEbItgZY2INbx9Yr0dqVEfMqCkVV"
)

var Auth0Domain = "dev-jm0tswj47qz2nlax.us.auth0.com"
var jwksURL = "https://dev-jm0tswj47qz2nlax.us.auth0.com/.well-known/jwks.json"
var Auth0ClientID = "weyssEbItgZY2INbx9Yr0dqVEfMqCkVV"
var Auth0ClientSecret = "vZ0vC1NclWF7DyFqCkge3esIq9bi69M2z0ZiuXlDTJPIL__-hOve_EoCCgN09tCd"

func OAuthTokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, "Authorization token is required", http.StatusUnauthorized)
			return
		}

		jwks, err := fetchJWKSet(jwksURL)
		if err != nil {
			http.Error(w, "Error fetching JWKS: "+err.Error(), http.StatusServiceUnavailable)
			return
		}

		if !validateToken(token, jwks) {
			http.Error(w, "Invalid or expired token - "+token, http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed with the request
		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	// Normally Bearer tokens are sent as 'Bearer {token}'
	tokenParts := strings.Split(bearerToken, " ")
	if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
		return tokenParts[1]
	}
	return ""
}

func validateToken(tokenString string, jwks jwk.Set) bool {
	token, err := jwt.Parse(tokenString, getKeyFunc(jwks))
	if err != nil {
		log.Printf("Failed to parse token: %s\nError: %s", tokenString, err.Error())
		return false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		iss := "https://" + Auth0Domain + "/"
		return claims.VerifyIssuer(iss, true) && claims.VerifyAudience(Auth0Audience, true)
	}

	return token.Valid
}

func fetchJWKSet(url string) (jwk.Set, error) {
	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	return set, nil
}

func getKeyFunc(jwks jwk.Set) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("expecting JWT header to have string kid")
		}

		key, ok := jwks.LookupKeyID(keyID)
		if !ok {
			return nil, fmt.Errorf("unable to find key %q", keyID)
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("unable to get raw key from JWKS key: %w", err)
		}

		return rawKey, nil
	}
}
