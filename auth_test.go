package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type blackList struct {
	repo map[string]struct{}
}

func newBlackList() *blackList {
	return &blackList{
		repo: map[string]struct{}{},
	}
}

func (list *blackList) AddKey(key string) error {
	list.repo[key] = struct{}{}
	return nil
}

func (list *blackList) Contains(key string) (bool, error) {
	if key == "error" {
		return false, errors.New("error")
	}
	_, ok := list.repo[key]
	return ok, nil
}

func TestValidate(t *testing.T) {
	auth := NewAuth("secret", 1*time.Second)
	list := newBlackList()

	testData := []struct {
		des     string
		sleep   time.Duration
		token   string
		sub     string
		err     bool
		signOut bool
	}{
		{
			des:   "valid token",
			token: auth.GenerateToken("user"),
			sub:   "user",
		},
		{
			des:   "invalid token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			err:   true,
		},
		{
			des:     "signed out token",
			token:   auth.GenerateToken("user"),
			err:     true,
			signOut: true,
		},
		{
			des:     "blacklist err",
			token:   "error",
			err:     true,
			signOut: true,
		},
		{
			des:   "expired token",
			sleep: 3 * time.Second,
			token: auth.GenerateToken("user"),
			err:   true,
		},
	}

	for _, td := range testData {
		t.Run(td.des, func(t *testing.T) {
			time.Sleep(td.sleep)
			if td.signOut {
				auth.SetBlackListStore(list)
				list.AddKey(td.token)
			}
			claims, err := auth.Validate(td.token)
			if td.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, td.sub, claims["sub"])
			}
		})
	}
}

func TestInvalidate(t *testing.T) {
	auth := NewAuth("secret", 1*time.Second)

	t.Run("signed out token", func(t *testing.T) {
		token := auth.GenerateToken("user")
		assert.Error(t, auth.Invalidate(token))
	})

	list := newBlackList()
	auth.SetBlackListStore(list)

	t.Run("signed out token", func(t *testing.T) {
		token := auth.GenerateToken("user")
		assert.NoError(t, auth.Invalidate(token))
		found, _ := list.Contains(token)
		assert.Equal(t, true, found)
	})
}
