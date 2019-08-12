package auth

import "errors"

var (
	// ErrTokenNotFound ...
	ErrTokenNotFound = errors.New("token not found")
	// ErrInvalidTokenFormat ...
	ErrInvalidTokenFormat = errors.New("invalid token format")
)
