// Package sso provide functions and client to communicate with WorkOS SSO API.
//
// Example:
//   func main() {
// 	     sso.SetAPIKey("my_api_key")
//
//       http.Handle("/login", sso.Login(sso.GetAuthorizationURLOptions{
// 	         Domain:      "mydomain.com",
// 	         ProjectID:   "my_workos_project_id",
// 	         RedirectURI: "https://mydomain.com/callback",
//       }))
//
// 	     http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
// 	         profile, err := sso.GetProfile(context.Background(), sso.GetProfileOptions{
// 	             Code:        r.URL.Query().Get("code"),
// 	             ProjectID:   "my_workos_project_id",
// 	             RedirectURI: "https://mydomain.com/callback",
// 	         })
// 	         if err != nil {
// 	             // Handle the error ...
// 	             return
// 	         }
//
// 	         // Handle the profile ...
// 	         fmt.Println(profile)
//       })
//
//       if err := http.ListenAndServe("your_server_addr", nil); err != nil {
//           panic(err)
//       }
//   }
package sso

import (
	"context"
	"net/http"
	"net/url"
)

const (
	version = "0.0.2"
)

var (
	// DefaultClient is the client used by SetAPIKey, GetAuthorizationURL,
	// GetProfile and Login functions.
	DefaultClient = &Client{}
)

// Init initializes default client api key and project id.
//
// Must be called before using GetAuthorizationURL, GetProfile or Login.
func Init(apiKey, projectID string) {
	DefaultClient.APIKey = apiKey
	DefaultClient.ProjectID = projectID
}

// GetAuthorizationURL returns an authorization url generated with the given
// options.
func GetAuthorizationURL(opts GetAuthorizationURLOptions) (*url.URL, error) {
	return DefaultClient.GetAuthorizationURL(opts)
}

// GetProfile returns a profile describing the user that authenticated with
// WorkOS SSO.
func GetProfile(ctx context.Context, opts GetProfileOptions) (Profile, error) {
	return DefaultClient.GetProfile(ctx, opts)
}

// Login return a http.Handler that redirects client to the appropriate
// login provider.
func Login(opts GetAuthorizationURLOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := GetAuthorizationURL(opts)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
}
