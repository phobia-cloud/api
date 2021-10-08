// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package handler_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"phobia.cloud/api/handler"
)

func TestChallenge(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	h := http.HandlerFunc(handler.Challenge)
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	decoder := json.NewDecoder(rr.Body)
	decoder.DisallowUnknownFields()

	var resp handler.ChallengeResponse
	err = decoder.Decode(&resp)
	require.NoError(t, err)

	assert.Len(t, resp.ChallengeHidden, 64)
	_, err = hex.DecodeString(resp.ChallengeHidden)
	assert.NoError(t, err)

	asTime, err := time.ParseInLocation("2006-01-02 15:04:05", resp.ChallengeVisual, time.Local)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), asTime, time.Minute)
}

func TestChallenge_MethodNotAllowed(t *testing.T) {
	for _, method := range []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {
		req, err := http.NewRequest(method, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		h := http.HandlerFunc(handler.Challenge)
		h.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code, method)
	}
}
