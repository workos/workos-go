package workos

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
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
	} else if isJsonResponse(r) {
		msg = getJsonErrorMessage(body)
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

func isJsonResponse(r *http.Response) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

func getJsonErrorMessage(b []byte) string {
	var payload struct {
		Message          string `json:"message"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	if err := json.Unmarshal(b, &payload); err != nil {
		return err.Error()
	}

	if payload.Error != "" && payload.ErrorDescription != "" {
		return fmt.Sprintf("%s %s", payload.Error, payload.ErrorDescription)
	} else if payload.Message != "" {
		return payload.Message
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
