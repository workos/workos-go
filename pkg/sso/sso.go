// Package sso provide functions and client to communicate with WorkOS SSO API.
//
// You first need to setup an SSO connection on
// https://dashboard.workos.com/sso/connections.
//
// Then implement the `/login` and `/callback` handlers on your server:
//   func main() {
//       sso.Configure(
//           "xxxxx",                         // WorkOS api key
//           "project_xxxxx",                 // WorkOS project id
//       )
//
//       http.Handle("/login", sso.Login(sso.GetAuthorizationURLOptions{
//           Domain:	"mydomain.com",
//           RedirectURI: "https://mydomain.com/callback",
//       }))
//
//       http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
//           profile, err := sso.GetProfile(context.Background(), sso.GetProfileOptions{
//               Code:	r.URL.Query().Get("code"),
//           })
//           if err != nil {
//               // Handle the error ...
//               return
//           }
//
//           // Handle the profile ...
//           fmt.Println(profile)
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

var (
	// DefaultClient is the client used by GetAuthorizationURL, GetProfile and
	// Login functions.
	DefaultClient = &Client{}
)

// Configure configures the default client that is used by GetAuthorizationURL,
// GetProfile and Login.
// It must be called before using those functions.
func Configure(apiKey, projectID, redirectURI string) {
	DefaultClient.APIKey = apiKey
	DefaultClient.ProjectID = projectID
	DefaultClient.RedirectURI = redirectURI
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

// PromoteDraftConnection promotes a draft connection created via the WorkOS.js Embed
// such that the Enterprise users can begin signing into your application.
//
// Deprecated: Use `CreateConnection` instead.
func PromoteDraftConnection(ctx context.Context, opts PromoteDraftConnectionOptions) error {
	return DefaultClient.PromoteDraftConnection(ctx, opts)
}

// CreateConnection promotes a Draft Connection created via the WorkOS.js widget.
func CreateConnection(ctx context.Context, opts CreateConnectionOpts) (Connection, error) {
	return DefaultClient.CreateConnection(ctx, opts)
}
