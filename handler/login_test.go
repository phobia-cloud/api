// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"phobia.cloud/api/handler"
)

func TestLogin(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "", strings.NewReader(`
		{
			"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
			"challengeVisual": "2015-03-23 17:39:22",
			"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
			"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
			"version": 2
		}
	`))
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	h := http.HandlerFunc(handler.Login)
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
	assert.Empty(t, rr.Body)
}

func TestLogin_Options(t *testing.T) {
	req, err := http.NewRequest(http.MethodOptions, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	h := http.HandlerFunc(handler.Login)
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, http.MethodPost, rr.Header().Get("Access-Control-Allow-Methods"))
}

func TestLogin_MissingBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	h := http.HandlerFunc(handler.Login)
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestLogin_MethodNotAllowed(t *testing.T) {
	for _, method := range []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodPatch,
		http.MethodPut,
		http.MethodTrace,
	} {
		req, err := http.NewRequest(method, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		h := http.HandlerFunc(handler.Login)
		h.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, method)
	}
}

func TestLogin_BadRequest(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
	}{
		{
			name: "empty body",
			body: "",
		},
		{
			name: "invalid json #1",
			body: "{",
		},
		{
			name: "invalid json #2",
			body: "}",
		},
		{
			name: "missing challenge hidden",
			body: `
				{
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 2
				}
			`,
		},
		{
			name: "missing challenge visual",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 2
				}
			`,
		},
		{
			name: "missing public key",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 2
				}
			`,
		},
		{
			name: "missing signature",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"version": 2
				}
			`,
		},
		{
			name: "missing challenge version",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
				}
			`,
		},
		{
			name: "wrong challenge hidden",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c1",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 2
				}
			`,
		},
		{
			name: "wrong challenge visual",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:21",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 2
				}
			`,
		},
		{
			name: "missing public key",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f44",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 2
				}
			`,
		},
		{
			name: "missing signature",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba01",
					"version": 2
				}
			`,
		},
		{
			name: "wrong version",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 1
				}
			`,
		},
		{
			name: "unsupported version",
			body: `
				{
					"challengeHidden": "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
					"challengeVisual": "2015-03-23 17:39:22",
					"publicKey": "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
					"signature": "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
					"version": 3
				}
			`,
		},
	} {
		req, err := http.NewRequest(http.MethodPost, "", strings.NewReader(tt.body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		h := http.HandlerFunc(handler.Login)
		h.ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code, tt.name)
	}
}
