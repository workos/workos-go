package workos_errors

import (
	"errors"
	"github.com/workos/workos-go/internal/workos"
	"net/http"
)

func IsBadRequest(err error) bool {
	var httpError workos.HTTPError
	return errors.As(err, &httpError) && httpError.Code == http.StatusBadRequest
}
