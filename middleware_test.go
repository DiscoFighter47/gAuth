package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gson "github.com/DiscoFighter47/gSON"

	"github.com/stretchr/testify/assert"
)

func testHandler() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		gson.ServeData(w, gson.Object{
			"msg": "Hello Secret Universe! Welcome " + r.Header.Get("Subject"),
		})
	}
	return http.HandlerFunc(fn)
}

func TestGatekeeper(t *testing.T) {
	auth := NewAuth("secret", 1*time.Second)
	token := auth.GenerateToken("user")
	svr := gson.Recoverer(auth.Gatekeeper(testHandler()))

	testData := []struct {
		sleep time.Duration
		des   string
		token string
		code  int
		res   string
	}{
		{
			des:   "valid authorization",
			token: "Bearer " + token,
			code:  http.StatusOK,
			res:   `{"data":{"msg":"Hello Secret Universe! Welcome user"}}`,
		},
		{
			des:   "no authorization",
			token: "",
			code:  http.StatusUnauthorized,
			res:   `{"error": {"title":"Authorization Required", "detail":"token not found"}}`,
		},
		{
			des:   "invalid authorization",
			token: "Bearertoken",
			code:  http.StatusUnprocessableEntity,
			res:   `{"error": {"title":"Unable To Extract Token", "detail":"invalid token format"}}`,
		},
		{
			des:   "invalid authorization",
			token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			code:  http.StatusUnauthorized,
			res:   `{"error": {"title":"Invalid Token", "detail":"signature is invalid"}}`,
		},
	}

	for _, td := range testData {
		t.Run(td.des, func(t *testing.T) {
			time.Sleep(td.sleep)
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Add("Authorization", td.token)
			res := httptest.NewRecorder()
			svr.ServeHTTP(res, req)
			assert.Equal(t, td.code, res.Code)
			assert.JSONEq(t, td.res, res.Body.String())
		})
	}
}
