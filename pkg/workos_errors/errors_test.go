package workos_errors_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/workos/workos-go/pkg/workos_errors"
)

func TestIsBadRequest(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "bad request",
			args: args{err: workos_errors.HTTPError{
				Code: http.StatusBadRequest,
			}},
			want: true,
		},
		{
			name: "internal server error",
			args: args{err: workos_errors.HTTPError{
				Code: http.StatusInternalServerError,
			}},
			want: false,
		},
		{
			name: "unknown error",
			args: args{err: fmt.Errorf("unknown error")},
			want: false,
		},
		{
			name: "nil",
			args: args{err: nil},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := workos_errors.IsBadRequest(tt.args.err); got != tt.want {
				t.Errorf("IsBadRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
