package client

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// PublishEvent delivers the Audit Log event to WorkOS.
func PublishEvent(body []byte) error {
	// Add retry logic
	// Ensure http.Client connection re-use
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	endpoint := os.Getenv("WORKOS_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:4567/audit-logs/events"
	}

	// Depending on size of body, look to encode with zlib
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	// Should error if not present
	apiKey := os.Getenv("WORKOS_API_KEY")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(bodyBytes))
	}

	return nil
}
