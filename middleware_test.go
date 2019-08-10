package gauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBearerToken(t *testing.T) {
	data := []struct {
		des     string
		brToken string
		token   string
		err     error
	}{
		{
			des:     "extract token",
			brToken: "Bearer token",
			token:   "token",
		},
		{
			des:     "extract token",
			brToken: "  Bearer  token  ",
			token:   "token",
		},
		{
			des:     "no token",
			brToken: "",
			err:     ErrTokenNotFound,
		},
		{
			des:     "invalid token",
			brToken: "Bearer",
			err:     ErrInvalidTokenFormat,
		},
		{
			des:     "invalid token",
			brToken: "Bearer ",
			err:     ErrInvalidTokenFormat,
		},
		{
			des:     "invalid token",
			brToken: "bearer",
			err:     ErrInvalidTokenFormat,
		},
	}

	for i := 0; i < len(data); i++ {
		t.Run(data[i].des, func(t *testing.T) {
			token, err := extractBearerToken(data[i].brToken)
			assert.Equal(t, data[i].err, err)
			assert.Equal(t, data[i].token, token)
		})
	}
}
