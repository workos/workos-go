package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/workos/workos-go/v2/pkg/common"
)

func mockClient(s *httptest.Server) *Client {
	client := NewClient("test", "client_123")
	client.HTTPClient = s.Client()
	client.Endpoint = s.URL
	return client
}

func TestLogin(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	DefaultClient = mockClient(server)

	redirectURI := server.URL + "/callback"

	profile := Profile{}
	expectedProfile := Profile{
		ID:             "profile_123",
		IdpID:          "123",
		OrganizationID: "org_123",
		ConnectionID:   "conn_123",
		ConnectionType: OktaSAML,
		Email:          "foo@test.com",
		FirstName:      "foo",
		LastName:       "bar",
		Groups:         []string{"Admins", "Developers"},
		RawAttributes: map[string]interface{}{
			"idp_id":     "123",
			"email":      "foo@test.com",
			"first_name": "foo",
			"last_name":  "bar",
		},
	}

	mux.Handle("/login", Login(GetAuthorizationURLOpts{
		Organization: "organization_123",
		RedirectURI:  redirectURI,
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
		p, err := GetProfileAndToken(context.Background(), GetProfileAndTokenOpts{
			Code: "authorization_code",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		profile = p.Profile

		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/sso/token", profileAndTokenTestHandler)

	res, err := server.Client().Get(server.URL + "/login")
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	require.Equal(t, expectedProfile, profile)
}

func TestSsoGetConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(getConnectionTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	expectedResponse := Connection{
		ID:             "conn_id",
		ConnectionType: "GoogleOAuth",
		State:          Active,
		Status:         Linked,
		Name:           "Foo Corp",
	}
	connectionResponse, err := GetConnection(context.Background(), GetConnectionOpts{
		Connection: "connection_id",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, connectionResponse)
}

func TestSsoListConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(listConnectionsTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)

	expectedResponse := ListConnectionsResponse{
		Data: []Connection{
			Connection{
				ID:             "conn_id",
				ConnectionType: "GoogleOAuth",
				State:          Active,
				Status:         Linked,
				Name:           "Foo Corp",
			},
		},
		ListMetadata: common.ListMetadata{
			Before: "",
			After:  "",
		},
	}
	connectionsResponse, err := ListConnections(
		context.Background(),
		ListConnectionsOpts{},
	)

	require.NoError(t, err)
	require.Equal(t, expectedResponse, connectionsResponse)
}

func TestSsoGetProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(profileTestHandler))
	defer server.Close()

	DefaultClient = mockClient(server)
	expectedResponse := Profile{
		ID:             "profile_123",
		IdpID:          "123",
		OrganizationID: "org_123",
		ConnectionID:   "conn_123",
		ConnectionType: OktaSAML,
		Email:          "foo@test.com",
		FirstName:      "foo",
		LastName:       "bar",
		Groups:         []string{"Admins", "Developers"},
		RawAttributes: map[string]interface{}{
			"idp_id":     "123",
			"email":      "foo@test.com",
			"first_name": "foo",
			"last_name":  "bar",
		},
	}
	profileResponse, err := GetProfile(context.Background(), GetProfileOpts{
		AccessToken: "access_token",
	})

	require.NoError(t, err)
	require.Equal(t, expectedResponse, profileResponse)
}
