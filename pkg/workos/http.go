package workos

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/tidwall/gjson"
)

// TryGetHTTPError returns an error when the http response contains invalid
// status code.
func TryGetHTTPError(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		return nil
	}

	var msg string

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		msg = err.Error()
	} else if m := gjson.GetBytes(body, "message").Str; m != "" {
		msg = m
	} else {
		msg = string(body)
	}

	return HTTPError{
		Code:      r.StatusCode,
		Status:    r.Status,
		RequestID: r.Header.Get("X-Request-ID"),
		Message:   msg,
	}
}

// HTTPError represents an http error.
type HTTPError struct {
	Code      int
	Status    string
	RequestID string
	Message   string
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("%s: request id %q: %s", e.Status, e.RequestID, e.Message)
}
