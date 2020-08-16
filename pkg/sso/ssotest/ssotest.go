// Package ssotest provides a fake in memory implementation of the WorkOS server.
package ssotest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/workos-inc/workos-go/pkg/sso"
)

// Server is an in memory, not threadsafe implementation of the WorkOS server.
// It can be used to create high fidelity in memory tests of your WorkOS
// integration. This server only implements the SSO related endpoints used to
// initiate and finalize a login. If you need more functionality, please
// talk to us and we can figure out next steps.
type Server struct {
	httpServer *httptest.Server

	emailToProfile map[string]sso.Profile
	// Note that codeToProfile is separate from email to profile so you can be
	// maximally flexible on code => profile mapping.
	codeToProfile map[string]sso.Profile
}

// New constructs a fake WorkOS server and also returns a cleanup function that
// must be called when the server is no longer needed.
func New() (*Server, func()) {
	s := &Server{
		emailToProfile: map[string]sso.Profile{},
		codeToProfile:  map[string]sso.Profile{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sso/token", s.token)
	mux.HandleFunc("/sso/authorize", s.authorize)

	// Start a local HTTP server (NewServer actually starts it).
	s.httpServer = httptest.NewServer(mux)

	return s, s.cleanup
}

// Client returns a sso.Client preconfigured to talk to this in memory fake.
func (s *Server) Client() *sso.Client {
	return &sso.Client{
		APIKey:    s.APIKey(),
		ProjectID: s.ProjectID(),
		Endpoint:  s.Endpoint(),
	}
}

// LoginLinkForEmail looks up the code associated with the email provided and
// returns the modified redirectURI with that login code added.  This returns
// *a* valid login link but if you have generated multiple login codes for this
// email, you will non-deterministically get back different codes every time.
func (s *Server) LoginLinkForEmail(redirectURI, email string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		panic(fmt.Sprintf("url.Parse(%q)", redirectURI))
	}

	for code, profile := range s.codeToProfile {
		if profile.Email == email {
			u.RawQuery = url.Values{
				"code": []string{code},
			}.Encode()
			return u.String()
		}
	}
	panic(fmt.Sprintf("No code for the email %q exists", email))
}

// CreateFakeProfile creates a user in the fake server and associates a profile
// with it. When you attempt to log in to a particular domain you will be
// presented with all the profiles who's email's domains match the domain
// you're attempting to SSO into. For example user@foo-corp.com would be
// presented as a login option when you attempt to SSO into the domain
// foo-corp.com.
func (s *Server) CreateFakeProfile(profile sso.Profile) {
	if profile.Email == "" {
		panic(fmt.Sprintf("The provided profile must have an email, got empty string."))
	}
	s.emailToProfile[profile.Email] = profile
}

// APIKey is the fake api token to use when communicating with this service.
func (s *Server) APIKey() string {
	return "API-TOKEN-FOR-WORKOS-FAKE"
}

// ProjectID is the fake project ID to use when communicating with this service.
func (s *Server) ProjectID() string {
	return "PROJECT-ID-FOR-WORKOS-FAKE"
}

// This is the endpoint URL used as the base for talking to WorkOS.
func (s *Server) Endpoint() string {
	return s.httpServer.URL
}

// cleanup is what is passed to the caller and should be invoked at the end of a test.
func (s *Server) cleanup() {
	// Close the server when test finishes
	s.httpServer.Close()
}

// token == /sso/token
// token is only ever called by an integrating server.
func (s *Server) token(rw http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, fmt.Sprintf("ioutil.ReadAll(r.Body): %v", err), 500)
		return
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(rw, fmt.Sprintf("url.ParseQuery(%q): %v", body, err), 500)
		return
	}

	code := params.Get("code")
	profile, ok := s.codeToProfile[code]
	if !ok {
		var codes []string
		for key := range s.codeToProfile {
			codes = append(codes, key)
		}
		http.Error(rw, fmt.Sprintf("No profile by the code %q found. Only have codes: %v", code, codes), 400)
		return
	}

	response := struct {
		Profile     sso.Profile `json:"profile"`
		AccessToken string      `json:"access_token"`
	}{
		Profile:     profile,
		AccessToken: generateCode(),
	}

	responseJSON, err := json.Marshal(&response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), 500)
		return
	}

	fmt.Fprintf(rw, "%s", responseJSON)
}

// authorize == /sso/authorize
// authorize is only ever called by a browser.
func (s *Server) authorize(rw http.ResponseWriter, r *http.Request) {
	// Extract all the state information.
	clientID := r.URL.Query().Get("client_id")
	domain := r.URL.Query().Get("domain")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")

	if clientID != s.ProjectID() {
		http.Error(rw, fmt.Sprintf("The provided client_id, %q, should be %q", clientID, s.ProjectID()), 500)
		return
	}

	if responseType != "code" {
		http.Error(rw, fmt.Sprintf("The requested response_type of, %q, isn't handled by this fake. It only handles \"code\"", clientID), 500)
		return
	}

	// Make a lookup table of each domain to the emails in it to determine if we can just log the user in directly.
	lookup := map[string][]string{}
	for email := range s.emailToProfile {
		if domain == domainFromEmail(email) {
			lookup[domain] = append(lookup[domain], email)
		}
	}

	switch len(lookup[domain]) {
	case 0:
		http.Error(rw, fmt.Sprintf("The requested domain has no emails preregistered with the fake, please register a profile in the domain %q", domain), 400)
		return
	case 1:
		// It only has one entry! no need to prompt the user for their idenitty
		email := lookup[domain][0]
		code := generateCode()
		s.codeToProfile[code] = s.emailToProfile[email]

		u, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(rw, fmt.Sprintf("url.Parse(%q)", redirectURI), 500)
			return
		}
		u.RawQuery = url.Values{
			"code": []string{code},
		}.Encode()

		http.Redirect(rw, r, u.String(), 302)
		return
	default:
		rw.Header().Set("Content-Type", "text/html") // and this
		// There are multiple users registered in this domain, present a list of
		// them for the user to select from.
		fmt.Fprintf(rw, "<h1>Available logins for %q</h1>", domain)
		fmt.Fprintf(rw, "<ul>")
		for _, email := range lookup[domain] {
			// It only has one entry! no need to prompt the user for their idenitty
			code := generateCode()
			s.codeToProfile[code] = s.emailToProfile[email]

			u, err := url.Parse(redirectURI)
			if err != nil {
				http.Error(rw, fmt.Sprintf("url.Parse(%q)", redirectURI), 500)
				return
			}
			u.RawQuery = url.Values{
				"code": []string{code},
			}.Encode()

			fmt.Fprintf(rw, `<li><a href="%s">%s</a></li>`, u.String(), email)
		}
		fmt.Fprintf(rw, "</ul>")
		return
	}
}

// generateCode generates a 40 character A-Z string that is roughly shaped like a code.
func generateCode() string {
	var buf string
	for i := 0; i < 40; i++ {
		buf += string(rune('A') + rune(rand.Intn(26)))
	}
	return buf
}

// domainFromEmail extracs the domain from an email.
func domainFromEmail(email string) string {
	return email[strings.LastIndex(email, "@")+1:]
}
