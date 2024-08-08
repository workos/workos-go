package retryablehttp

import (
	"io"
	"math"
	"math/rand"
	"net/http"
	"time"
)

const MaxRetryAttempts = 3
const MinimumDelay = 500
const MinimumDelayDuration = 250 * time.Millisecond
const MaximumDelayDuration = 5 * time.Second
const RandomizationFactor = 0.5
const BackoffMultiplier = 1.5

type HttpClient struct {
	http.Client
}

func (client *HttpClient) Do(req *http.Request) (*http.Response, error) {
	var res *http.Response
	var err error
	for retry := 0; ; {
		// Reset the request body for each retry
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				client.CloseIdleConnections()
				return res, err
			}
			if c, ok := body.(io.ReadCloser); ok {
				req.Body = c
			} else {
				req.Body = io.NopCloser(body)
			}
		}

		res, err = client.Client.Do(req)
		if err != nil {
			break
		}

		shouldRetry := client.shouldRetry(req, res, err, retry)

		if !shouldRetry {
			break
		}

		sleepTime := client.sleepTime(retry)
		retry++

		timer := time.NewTimer(sleepTime)
		select {
		case <-req.Context().Done():
			timer.Stop()
			client.CloseIdleConnections()
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (client *HttpClient) shouldRetry(req *http.Request, resp *http.Response, err error, retryAttempt int) bool {
	if retryAttempt >= MaxRetryAttempts {
		return false
	}

	if err != nil {
		return true
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return true
	}

	return false
}

// Calculates backoff time using exponential backoff with 50% jitter.
//
// Backoff times
// Retry Attempt | Sleep Time
// 1             | 500ms +/- 250ms
// 2             | 750ms +/- 375ms
// 3             | 1.125s +/- 562ms
func (client *HttpClient) sleepTime(retryAttempt int) time.Duration {
	sleepTime := time.Duration(MinimumDelay*int64(math.Pow(BackoffMultiplier, float64(retryAttempt)))) * time.Millisecond

	delta := RandomizationFactor * float64(sleepTime)
	minSleep := float64(sleepTime) - delta
	maxSleep := float64(sleepTime) + delta

	sleepTime = time.Duration(minSleep + (rand.Float64() * (maxSleep - minSleep + 1)))

	if sleepTime < MinimumDelayDuration {
		sleepTime = MinimumDelayDuration
	} else if sleepTime > MaximumDelayDuration {
		sleepTime = MaximumDelayDuration
	}

	return sleepTime
}
