package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBearerToken(t *testing.T) {
	testData := []struct {
		des   string
		token string
		res   string
		err   bool
	}{
		{
			des:   "valid token",
			token: "Bearer token",
			res:   "token",
		},
		{
			des:   "valid token",
			token: "  Bearer  token  ",
			res:   "token",
		},
		{
			des:   "invalid token",
			token: "",
			err:   true,
		},
		{
			des:   "invalid token",
			token: "Bearer",
			err:   true,
		},
		{
			des:   "invalid token",
			token: "Basic token",
			err:   true,
		},
	}

	for _, td := range testData {
		t.Run(td.des, func(t *testing.T) {
			token, err := ExtractBearerToken(td.token)
			if td.err {
				assert.Error(t, err)
			} else {
				assert.Equal(t, td.res, token)
			}
		})
	}
}
