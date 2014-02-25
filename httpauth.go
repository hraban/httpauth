// Package httpauth provides http.Handlers that handle standard HTTP
// authentication methods.
package httpauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Basic creates an http.Handler that perfoms basic authentication on
// incoming HTTP request. The given realm is passed to browsers or
// clients who attempt to connect without authenticating. The given
// authFunc is used to authenticate a client with the parameters
// passed being the user name and password. If authentication
// succeeds, the onSuccess handler is called with the request. If
// authentication fails, the client receives a 401 unauthorized.
func Basic(realm string, onSuccess http.Handler, authFunc func(string, string) bool) http.Handler {
	return &handler{
		method:  "Basic",
		realm:   realm,
		success: onSuccess,
		auth:    authFunc,
	}
}

type handler struct {
	method  string
	realm   string
	success http.Handler
	auth    func(string, string) bool
}

func (h *handler) fail(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`%s realm="%s"`,
		h.method, h.realm))
	w.WriteHeader(http.StatusUnauthorized)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the header, split it out, and verify it is "Basic".
	a := r.Header.Get("Authorization")
	if a == "" {
		h.fail(w)
		return
	}
	parts := strings.Split(a, " ")
	if len(parts) != 2 {
		h.fail(w)
		return
	}
	if parts[0] != h.method {
		h.fail(w)
		return
	}

	// Decode the user:password, verify it's formatted correct, and call
	// auth.
	creds, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		h.fail(w)
		return
	}
	parts = strings.Split(string(creds), ":")
	if len(parts) != 2 {
		h.fail(w)
		return
	}
	if !h.auth(parts[0], parts[1]) {
		h.fail(w)
		return
	}

	// If all went well, then call the wrapped handler.
	h.success.ServeHTTP(w, r)
}
