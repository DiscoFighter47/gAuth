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
	store         BlackList
}

// NewAuth ...
func NewAuth(secret string, exp time.Duration) *Auth {
	return &Auth{
		method:        jwt.SigningMethodHS256,
		expireTimeout: exp,
		secret:        secret,
	}
}

// SetBlackListStore ...
func (auth *Auth) SetBlackListStore(store BlackList) {
	auth.store = store
}

// GenerateToken ...
func (auth *Auth) GenerateToken(sub string) string {
	id, _ := uuid.NewUUID()
	token, _ := jwt.NewWithClaims(auth.method, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(auth.expireTimeout).Unix(),
		Id:        id.String(),
		IssuedAt:  time.Now().Unix(),
		Subject:   sub,
	}).SignedString([]byte(auth.secret))
	return token
}

func (auth *Auth) parser(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(auth.secret), nil
}

// Validate ...
func (auth *Auth) Validate(token string) (jwt.MapClaims, error) {
	if auth.store != nil {
		found, err := auth.store.Contains(token)
		if err != nil {
			return nil, err
		}
		if found {
			return nil, ErrSignedOutToken
		}
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, auth.parser)
	return claims, err
}

// Invalidate ...
func (auth *Auth) Invalidate(token string) error {
	if auth.store == nil {
		return ErrUnsupportedOperation
	}
	return auth.store.AddKey(token)
}
