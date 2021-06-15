package workos

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetHTTPErrorWithJSONPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`{"message":"unauthorized", "error": "unauthorized error", "error_description": "unauthorized error description"}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Equal(t, "GOrOXx", httperr.RequestID)
	require.Equal(t, "unauthorized", httperr.Message)
	require.Equal(t, "unauthorized error", httperr.Err)
	require.Equal(t, "unauthorized error description", httperr.ErrDescription)

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
	rec.WriteHeader(http.StatusUnauthorized)
	rec.WriteString(`{"message":"unauthorized", "error": "unauthorized error", "error_description": "unauthorized error description"}`)

	err := TryGetHTTPError(rec.Result())
	require.Error(t, err)

	httperr := err.(HTTPError)
	require.Equal(t, http.StatusUnauthorized, httperr.Code)
	require.Equal(t, "401 Unauthorized", httperr.Status)
	require.Empty(t, httperr.RequestID)
	require.Equal(t, "unauthorized", httperr.Message)
	require.Equal(t, "unauthorized error", httperr.Err)
	require.Equal(t, "unauthorized error description", httperr.ErrDescription)

	t.Log(httperr)
}

func TestGetHTTPErrorNoError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "GOrOXx")
	rec.WriteHeader(http.StatusOK)

	err := TryGetHTTPError(rec.Result())
	require.NoError(t, err)
}
