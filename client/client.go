package client

import (
	"bytes"
	"fmt"
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
		endpoint = "http://localhost:4567/receive"
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	// Should error if not present
	apiKey := os.Getenv("WORKOS_API_KEY")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		return fmt.Errorf("Received a %d", resp.StatusCode)
	}

	return nil
}
