package ssotest_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/workos-inc/workos-go/pkg/sso"
	"github.com/workos-inc/workos-go/pkg/sso/ssotest"
)

// Example demonstrates a very simple, but working server that will allow
// logins and prompt if you attempt to login to a domain that has multiple
// profiles already installed in it.
func Example() {
	// Start by creating a new ssotest server.
	workOSServer, cleanup := ssotest.New()
	// Don't forget to call cleanup when you're done!
	defer cleanup()

	// Get a WorkOS SSO Client from the server that is preconfigured.
	workOSClient := workOSServer.Client()

	// Register some profiles that can be logged in as. Just make sure to go to
	// /login?domain=$THE_DOMAIN_ASSOCIATED_WITH_THE_EMAIL.
	workOSServer.CreateFakeProfile(sso.Profile{
		FirstName:      "Morty",
		LastName:       "Smith",
		Email:          "msmith@curse-purge-plus.example",
		ConnectionType: sso.GenericSAML,
		ID:             "morty_identification",
		IdpID:          "morty_idpidentification",
	})
	workOSServer.CreateFakeProfile(sso.Profile{
		FirstName:      "Rick",
		LastName:       "Sanchez",
		Email:          "rsanchez@curse-purge-plus.example",
		ConnectionType: sso.GenericSAML,
		ID:             "rick_identification",
		IdpID:          "rick_idpidentification",
	})
	workOSServer.CreateFakeProfile(sso.Profile{
		FirstName:      "Tammy",
		LastName:       "Gueterman",
		Email:          "tgueterman@glactic-federation.example",
		ConnectionType: sso.GoogleOAuth,
		ID:             "tammy_identification",
		IdpID:          "tammy_idpidentification",
	})

	// This mux is the one you're using to serve your normal traffic. We're going
	// to register the /login and /callback handlers into this mux so your users
	// have a place they can login.
	mux := http.NewServeMux()

	// Normally
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		opts := sso.GetAuthorizationURLOptions{
			Domain:      r.URL.Query().Get("domain"),
			RedirectURI: "http://localhost:8080/callback",
		}
		u, err := workOSClient.GetAuthorizationURL(opts)
		if err != nil {
			http.Error(w, fmt.Sprintf("GetAuthorizationURL(%v): %v", opts, err.Error()), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})

	mux.HandleFunc("/callback", func(rw http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(rw, fmt.Sprintf("No code provided in /callback"), 500)
			return
		}
		profile, err := workOSClient.GetProfile(r.Context(), sso.GetProfileOptions{
			Code: code,
		})
		if err != nil {
			http.Error(rw, fmt.Sprintf("sso.GetProfile(%q): %v", code, err), 500)
			return
		}

		profileJSON, err := json.Marshal(&profile)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Error encoding profile: %v", err), 500)
			return
		}

		fmt.Fprintf(rw, "%s", profileJSON)
	})

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Fatal(httpServer.ListenAndServe())
}
