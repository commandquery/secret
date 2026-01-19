package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/commandquery/secrt"
)

// Validate an enrolment token and code. This is mostly used for testing
// but I suppose if you somehow get a validation code but can't enter it,
// you can do it here.

func CmdValidate(config *Config, endpoint *Endpoint, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: secrt validate <token> <code>")
	}

	code, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid code: %v", err)
	}

	validationRequest := &secrt.ValidationRequest{
		Token: args[0],
		Code:  code,
	}

	endpointURL := endpoint.Path("validate")

	body, err := json.Marshal(validationRequest)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewReader(body))
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

	// TODO ... something
	return nil
}
