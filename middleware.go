package gauth

import (
	"fmt"
	"net/http"
	"strings"

	gson "github.com/DiscoFighter47/gSON"
)

// Gatekeeper ...
func (auth *Auth) Gatekeeper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r.Header.Get("Authorization"))
		if err != nil {
			panic(gson.NewAPIerror("Unable To Extract Token", http.StatusUnprocessableEntity, err))
		}
		claims, err := auth.Validate(token)
		if err != nil {
			panic(gson.NewAPIerror("Invalid Token", http.StatusUnauthorized, err))
		}
		r.Header.Add("subject", fmt.Sprintf("%v", claims["sub"]))
		next.ServeHTTP(w, r)
	})
}

func extractBearerToken(token string) (string, error) {
	if token == "" {
		return "", ErrTokenNotFound
	}
	splitToken := strings.Split(token, "Bearer ")
	if len(splitToken) != 2 || splitToken[1] == "" {
		return "", ErrInvalidTokenFormat
	}
	return strings.TrimSpace(splitToken[1]), nil
}
