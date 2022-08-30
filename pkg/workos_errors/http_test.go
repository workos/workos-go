package workos_errors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHTTPErrorWithJSONPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`{"message":"unauthorized", "error": "unauthorized error", "error_description": "unauthorized error description"}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "unauthorized error unauthorized error description", httperr.Message)

	t.Log(httperr)
}

func TestGetHTTPErrorWith400StatusCodeJSONPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusBadRequest)
	rec.WriteString(`{"message":"Invalid Audit", "code": "invalid_audit_logs", "errors": ["another_error"]}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusBadRequest, httperr.Code)
	require.Equal(t, "400 Bad Request", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "Invalid Audit", httperr.Message)
	require.Equal(t, "invalid_audit_logs", httperr.ErrorCode)
	require.Equal(t, []string{"another_error"}, httperr.Errors)

	t.Log(httperr)
}

func TestGetHTTPErrorWith422StatusCodeJSONPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnprocessableEntity)
	rec.WriteString(`{"message":"Validation failed", "errors": [{"field": "name", "code": "required"}]}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnprocessableEntity, httperr.Code)
	require.Equal(t, "422 Unprocessable Entity", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "Validation failed", httperr.Message)
	require.Equal(t, []FieldError{{Field: "name", Code: "required"}}, httperr.FieldErrors)

	t.Log(httperr)
}

func TestGetHTTPErrorWithInvalidJSONPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`unauthorized`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "unauthorized", httperr.Message)

	t.Log(httperr)
}

func TestGetHTTPErrorWithExtendedJSONContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.Header().Set("Content-Type", "application/json; charset=utf8")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`{"message":"not unauthorized"}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "not unauthorized", httperr.Message)

	t.Log(httperr)
}

func TestGetHTTPErrorWithTextPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString("unauthorized msg")

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "unauthorized msg", httperr.Message)

	t.Log(httperr)
}

func TestGetHTTPErrorWithoutRequestID(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`{"message":"unauthorized", "error": "unauthorized error", "error_description": "unauthorized error description"}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Empty(t, httperr.RequestID)
	require.Equal(t, "unauthorized error unauthorized error description", httperr.Message)

	t.Log(httperr)
}

func TestGetHTTPErrorWithoutErrorOrErrorDescription(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`{"message":"unauthorized"}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "unauthorized", httperr.Message)

	t.Log(httperr)
}

func TestGetHTTPErrorNoError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.WriteHeader(http.StatusOK)

	err := TryGetHTTPError(rec.Result())
	require.NoError(t, err)
}
