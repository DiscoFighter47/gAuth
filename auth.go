package auth

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// Auth ...
type Auth struct {
	method        jwt.SigningMethod
	expireTimeout time.Duration
	secret        string
}

// NewAuth ...
func NewAuth(secret string, exp time.Duration) *Auth {
	return &Auth{
		method:        jwt.SigningMethodHS256,
		expireTimeout: exp,
		secret:        secret,
	}
}

// GenerateToken ...
func (auth *Auth) GenerateToken(sub string) (string, error) {
	id, _ := uuid.NewUUID()
	return jwt.NewWithClaims(auth.method, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(auth.expireTimeout).Unix(),
		Id:        id.String(),
		IssuedAt:  time.Now().Unix(),
		Subject:   sub,
	}).SignedString([]byte(auth.secret))
}

func (auth *Auth) parser(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(auth.secret), nil
}

// Validate ...
func (auth *Auth) Validate(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, auth.parser)
	return claims, err
}
