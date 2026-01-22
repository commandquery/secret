package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/commandquery/secrt"
)

// EMPTY is the type you should use as the request type if the request body or response should be empty.
type EMPTY struct{}

var CtxRequestKey struct{}

// GetRequest gets the HTTP request object from the context passed into a JSON handler.
// Panics if the request isn't present (since it definitely should be).
func GetRequest(ctx context.Context) *http.Request {
	return ctx.Value(CtxRequestKey).(*http.Request)
}

// dispatch returns a http.ServeFunc that calls a function that defines an input and output object type,
// which is automatically converted to/from JSON.
// This makes operations that receive and produce JSON typesafe (no conversions needed), error safe (error
// states always return), and super simple (zero boilerplate).
//
// If either the IN type is declared as the type EMPTY, nothing is read from the request body.
// If the return (non-error) value is nil, nothing is written to the response.
func dispatch[IN any, OUT any](method func(*SecretServer, context.Context, *IN) (*OUT, *secrt.HTTPError)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := GetHostname(r)
		s, err := GetSecretServer(host)
		if err != nil {
			LogError(w, http.StatusNotFound, err)
			return
		}

		// If the request type (IN) is not the type EMPTY, read the body.
		var in IN
		if _, ok := any(in).(EMPTY); !ok {
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				LogError(w, http.StatusBadRequest, err)
				return
			}
		}

		ctx := context.WithValue(r.Context(), CtxRequestKey, r)

		out, httpErr := method(s, ctx, &in)
		if httpErr != nil {
			LogError(w, httpErr.StatusCode, httpErr.Err)
			return
		}

		if out != nil {
			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(out)
			if err != nil {
				// It's probably too late to do anything at this point.
				LogError(w, http.StatusBadRequest, err)
			}
		}
	}
}

func WriteError(w http.ResponseWriter, err error) {
	log.Println(err)
	switch {
	case errors.Is(err, ErrUnknownMessageID):
		http.Error(w, "unknown message id", http.StatusNotFound)
		return
	case errors.Is(err, ErrAmbiguousMessageID):
		http.Error(w, "ambiguous message id", http.StatusConflict)
		return
	default:
		_ = WriteStatus(w, http.StatusInternalServerError, err)
		return
	}
}

// WriteStatus sets the HTTP status and sends a message. Returns the provided
// error, making it possible to call WriteStatus and return with an error in a single
// statement.
func WriteStatus(w http.ResponseWriter, status int, err error) error {
	http.Error(w, http.StatusText(status), status)
	return err
}

// LogError is like WriteStatus but logs the error, and doesn't return it.
func LogError(w http.ResponseWriter, status int, err error) {
	if err != nil {
		log.Printf("%v (http %d)", err, status)
	} else {
		log.Printf("http %d", status)
	}
	http.Error(w, http.StatusText(status), status)
}

func GetHostname(r *http.Request) string {
	host, _, _ := strings.Cut(r.Host, ":")
	return host
}
