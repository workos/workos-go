package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogin(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	redirectURI := server.URL + "/callback"

	profile := Profile{}
	expectedProfile := Profile{
		ID:             "proj_123",
		IdpID:          "123",
		ConnectionID:   "conn_123",
		ConnectionType: OktaSAML,
		Email:          "foo@test.com",
		FirstName:      "foo",
		LastName:       "bar",
		RawAttributes: map[string]interface{}{
			"idp_id":     "123",
			"email":      "foo@test.com",
			"first_name": "foo",
			"last_name":  "bar",
		},
	}

	wg := sync.WaitGroup{}
	wg.Add(1)

	mux.Handle("/login", Login(GetAuthorizationURLOptions{
		Domain:      "lyft.com",
		RedirectURI: redirectURI,
	}))

	mux.HandleFunc("/sso/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect_uri")

		res, err := server.Client().Get(redirect)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		res.Body.Close()

		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		p, err := GetProfile(context.Background(), GetProfileOptions{
			Code: "authorization_code",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		profile = p

		w.WriteHeader(http.StatusOK)
		wg.Done()
	})

	mux.HandleFunc("/sso/token", profileTestHandler)

	DefaultClient = &Client{
		Endpoint:   server.URL,
		HTTPClient: server.Client(),
	}
	Configure("test", "proj_123", redirectURI)

	res, err := server.Client().Get(server.URL + "/login")
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	wg.Wait()
	require.Equal(t, expectedProfile, profile)
}
