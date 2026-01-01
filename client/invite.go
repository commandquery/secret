package client

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
)

func CmdInvite(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		secrt.Usage("secret invite user@domain")
	}

	args = flags.Args()
	if len(args) != 1 {
		secrt.Usage("secret invite user@domain")
	}

	endpointURL := endpoint.Path("invite", args[0])

	req, err := http.NewRequest("POST", endpointURL, nil)
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
		return fmt.Errorf("peer %s not found", args[0])
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return config.Save()
}
