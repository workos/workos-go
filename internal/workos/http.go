package workos

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
	} else {
		msg = getJsonErrorMessage(body)
	}

	return HTTPError{
		Code:      r.StatusCode,
		Status:    r.Status,
		RequestID: r.Header.Get("X-Request-ID"),
		Message:   msg,
	}
}

func getJsonErrorMessage(b []byte) string {
	var r struct {
		Message          string `json:"message"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	if err := json.Unmarshal(b, &r); err != nil {
		return string(b)
	}

	if r.Error != "" && r.ErrorDescription != "" {
		return fmt.Sprintf("%s %s", r.Error, r.ErrorDescription)
	} else if r.Message != "" {
		return r.Message
	}

	return string(b)
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
