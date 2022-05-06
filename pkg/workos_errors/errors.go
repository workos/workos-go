package workos_errors

import (
	"errors"
	"net/http"
)

func IsBadRequest(err error) bool {
	var httpError HTTPError
	return errors.As(err, &httpError) && httpError.Code == http.StatusBadRequest
}
