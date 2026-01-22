package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/commandquery/secrt"
)

var client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	},
}

var EMPTY = &emptyTag{}

type emptyTag struct{}

type JSONRequest[S any, R any] struct {
	ctx      context.Context
	endpoint *Endpoint
	method   string
	path     []string
	headers  http.Header
	signed   bool
	send     S
	recv     *R
}

// Call sends a JSON object and receives a JSON response. It's a convenience method that
// creates a JSONRequest and calls it. The intent is that most calls should use
// this method, but some requests are more complex and require additional settings
// (unsigned requests, headers, etc).
func Call[S any, R any](endpoint *Endpoint, s S, r *R, method string, path ...string) error {
	request := JSONRequest[S, R]{
		ctx:      context.Background(),
		endpoint: endpoint,
		method:   method,
		path:     path,
		signed:   true,
		send:     s,
		recv:     r,
	}

	return JSONCall[S, R](&request)
}

func JSONCall[S any, R any](r *JSONRequest[S, R]) error {

	var reader io.Reader = http.NoBody

	// If the request isn't EMPTY, serialise and send it.
	if _, ok := any(r.send).(*emptyTag); !ok {
		js, err := json.Marshal(r.send)
		if err != nil {
			return fmt.Errorf("unable to marshal json: %v", err)
		}

		reader = bytes.NewReader(js)
	}

	req, err := http.NewRequestWithContext(r.ctx, r.method, r.endpoint.Path(r.path...), reader)
	if err != nil {
		return err
	}

	if r.signed {
		if err = r.endpoint.SetSignature(req); err != nil {
			return fmt.Errorf("unable to set signature: %w", err)
		}
	}

	if reader != http.NoBody {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if r.headers != nil {
		for k, v := range r.headers {
			for _, val := range v {
				req.Header.Add(k, val)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &secrt.HTTPError{StatusCode: resp.StatusCode}
	}

	if _, ok := any(r.recv).(*emptyTag); ok {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %w", err)
	}

	if err = json.Unmarshal(body, r.recv); err != nil {
		return fmt.Errorf("unable to unmarshal response: %w", err)
	}

	return nil
}
