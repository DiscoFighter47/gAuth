package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuth(t *testing.T) {
	auth := NewAuth("secret", 1*time.Second)
	token, err := auth.GenerateToken("user1")

	t.Run("generate token", func(t *testing.T) {
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("validate token", func(t *testing.T) {
		claims, err := auth.Validate(token)
		assert.NoError(t, err)
		assert.Equal(t, "user1", claims["sub"])
	})

	t.Run("expired token", func(t *testing.T) {
		time.Sleep(2 * time.Second)
		_, err := auth.Validate(token)
		assert.Error(t, err)
	})

	t.Run("invalid token", func(t *testing.T) {
		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		_, err := auth.Validate(token)
		assert.Error(t, err)
	})
}
