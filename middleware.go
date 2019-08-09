package gauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	gson "github.com/DiscoFighter47/gSON"
)

// Gatekeeper ...
func (auth *Auth) Gatekeeper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
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

func extractBearerToken(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	splitToken := strings.Split(token, "Bearer")
	if len(splitToken) != 2 {
		return "", errors.New("invalid bearer token format")
	}
	return strings.TrimSpace(splitToken[1]), nil
}
