package gauth

import "errors"

var (
	// ErrTokenNotFound ...
	ErrTokenNotFound = errors.New("Token not found")
	// ErrInvalidTokenFormat ...
	ErrInvalidTokenFormat = errors.New("Invalid token format")
)
