package main

import (
	"fmt"
	"io"
	"net/http"
)

// CmdRm asks the server to delete a message.
func CmdRm(config *Config, endpoint *Endpoint, args []string) error {

	endpointURL := endpoint.Path("message", args[0])

	req, err := http.NewRequest("DELETE", endpointURL, nil)
	if err != nil {
		return err
	}

	if err = endpoint.SetSignature(req); err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("message %s not found", args[0])
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unable to delete message: %s %s", resp.Status, body)
	}

	return nil
}
