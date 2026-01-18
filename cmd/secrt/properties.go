package main

import (
	"fmt"
	"strconv"
)

// Properties is a set of configuration properties used to control
// the behaviour of the client.
type Properties struct {
	DefaultEndpoint int  `json:"defaultEndpoint"` // The default server to use
	AcceptPeers     bool `json:"acceptPeers"`     // Automatically accept new peers
}

func (p *Properties) Set(name string, value string) error {
	var err error

	switch name {
	case "server":
		p.DefaultEndpoint, err = strconv.Atoi(value)
	case "acceptPeers":
		p.AcceptPeers, err = strconv.ParseBool(value)
	default:
		err = fmt.Errorf("unknown property '%s'", name)
	}

	return err
}
