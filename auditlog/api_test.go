package auditlog

import (
	"strconv"
	"testing"
)

var limits = []struct {
	in  int
	out int
}{
	{1, 1},
	{-1, 50},
	{1001, 1000},
	{100, 100},
}

func TestEventsRequestParamsLimit(t *testing.T) {
	for _, tt := range limits {
		t.Run(strconv.Itoa(tt.in), func(t *testing.T) {
			params := EventsRequestParams{
				Limit: tt.in,
			}
			if params.limit() != tt.out {
				t.Errorf("got %q, wanted %q", params.limit(), tt.out)
			}
		})
	}
}
