package auth

import "strings"

// ExtractBearerToken ...
func ExtractBearerToken(token string) (string, error) {
	splitToken := strings.Split(token, "Bearer ")
	if len(splitToken) != 2 || splitToken[1] == "" {
		return "", ErrInvalidTokenFormat
	}
	return strings.TrimSpace(splitToken[1]), nil
}
