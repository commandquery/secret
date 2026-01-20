package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// EMPTY is the type you should use as the request type if the
// request body should be empty.
type EMPTY struct{}

type HTTPError struct {
	StatusCode int
	Err        error
}

func (e HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("Error: %s (http status %d)", e.Err.Error(), e.StatusCode)
	}
	return fmt.Sprintf("HTTP status %d", e.StatusCode)
}

var CtxRequestKey struct{}

// GetRequest gets the HTTP request object from the context passed into a JSON handler.
// Panics if the request isn't present (since it definitely should be).
func GetRequest(ctx context.Context) *http.Request {
	return ctx.Value(CtxRequestKey).(*http.Request)
}

// dispatchJS is a http.ServeFunc wrapper that makes operations that receive
// and produce JSON both typesafe, error safe, and super simple.
func dispatchJS[IN any, OUT any](method func(*SecretServer, context.Context, *IN) (*OUT, *HTTPError)) http.HandlerFunc {
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

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(out)
		if err != nil {
			// It's probably too late to do anything at this point.
			LogError(w, http.StatusBadRequest, err)
		}
	}
}

func ErrBadRequest(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusBadRequest,
		Err:        err,
	}
}

func ErrNotFound(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusNotFound,
		Err:        err,
	}
}

func ErrInternalServerError(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

func ErrForbidden(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusForbidden,
		Err:        err,
	}
}

func ErrUnauthorized(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusUnauthorized,
		Err:        err,
	}
}

func ErrConflict(err error) *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusConflict,
		Err:        err,
	}
}

func ErrNoContent() *HTTPError {
	return &HTTPError{
		StatusCode: http.StatusConflict,
		Err:        nil,
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
