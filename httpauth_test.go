package httpauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func ExampleBasic() {
	// Non-authenticated parts of the system can be added as normal to
	// any Handler (in this case the default.
	http.Handle("/", http.FileServer(http.Dir("public")))
	// Authenticated parts simply need to wrap the normal handler with
	// the Basic function. In this case, we wrap a FileServer handler
	// with Basic authentication and only use the FileServer is the
	// client authenticates with the username "test" and the password
	// "nothing".
	http.Handle("/private/", Basic("private area", http.FileServer(http.Dir("private")),
		func(user, pass string) bool {
			if user == "test" && pass == "nothing" {
				return true
			}
			return false
		}))
}

func TestBasic(t *testing.T) {
	tests := []struct {
		header string
		user   string
		pass   string
		code   int
		fail   bool
	}{
		// No header.
		{
			header: "",
			user:   "",
			pass:   "",
			code:   http.StatusUnauthorized,
			fail:   true,
		},
		// Header with size <> 2.
		{
			header: "Basic askd asdf",
			user:   "",
			pass:   "",
			code:   http.StatusUnauthorized,
			fail:   true,
		},
		// Header with wrong method.
		{
			header: "Digest askd=",
			user:   "",
			pass:   "",
			code:   http.StatusUnauthorized,
			fail:   true,
		},
		// Header with bad base64 encoding.
		{
			header: "Basic #%@",
			user:   "",
			pass:   "",
			code:   http.StatusUnauthorized,
			fail:   true,
		},
		// Header with more than two fields in the base64
		{
			header: "Basic dGVzdDpub3RoaW5nLzEyMzphYnM=",
			user:   "",
			pass:   "",
			code:   http.StatusUnauthorized,
			fail:   true,
		},
		// Normal test.
		{
			header: "Basic dGVzdDpub3RoaW5nLzEyMw==",
			user:   "test",
			pass:   "nothing/123",
			code:   http.StatusOK,
			fail:   false,
		},
		// failed auth
		{
			header: "Basic dGVzdDpub3RoaW5nLzEyMw==",
			user:   "test",
			pass:   "nothing/123",
			code:   http.StatusUnauthorized,
			fail:   true,
		},
	}

	user := ""
	pass := ""
	fail := false
	handler := Basic("test-realm",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("test-good"))
		}), func(u, p string) bool {
			user = u
			pass = p
			return !fail
		})

	for k, test := range tests {
		fail = test.fail
		req, err := http.NewRequest("GET", "http://example.com/foo", nil)
		if err != nil {
			t.Fatalf("Test %v: failed to make request: %v", k, err)
		}
		req.Header.Add("Authorization", test.header)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != test.code {
			t.Fatalf("Test %v: Response Code = %v, expected %v", k, w.Code, test.code)
		}
		if user != test.user {
			t.Errorf("Test %v: User = %v, expected %v", k, user, test.user)
		}
		if pass != test.pass {
			t.Errorf("Test %v: Pass = %v, expected %v", k, pass, test.pass)
		}
		if test.fail {
			expect := `Basic realm="test-realm"`
			if w.HeaderMap.Get("WWW-Authenticate") != expect {
				t.Errorf("Test %v: WWW-Authenticate = %v, expected %v", k,
					w.HeaderMap.Get("WWW-Authenticate"), expect)
			}
		} else {
			expect := "test-good"
			if w.Body.String() != expect {
				t.Errorf("Test %v: response body = %v, expected %v", k,
					w.Body.String(), expect)
			}
		}
	}
}
