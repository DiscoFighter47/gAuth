package auth

import "errors"

var (
	// ErrTokenNotFound ...
	ErrTokenNotFound = errors.New("token not found")
	// ErrInvalidTokenFormat ...
	ErrInvalidTokenFormat = errors.New("invalid token format")
	// ErrSignedOutToken ...
	ErrSignedOutToken = errors.New("token has been signed out")
	// ErrUnsupportedOperation ...
	ErrUnsupportedOperation = errors.New("unsupported operation")
)
