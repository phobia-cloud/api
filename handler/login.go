// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package handler

import (
	"encoding/json"
	"net/http"

	"phobia.cloud/api/login"
)

// LoginRequest contains the login information and signature to verify for
// Trezor login.
type LoginRequest struct {
	ChallengeHidden string `json:"challengeHidden"`
	ChallengeVisual string `json:"challengeVisual"`
	PublicKey       string `json:"publicKey"`
	Signature       string `json:"signature"`
	Version         int    `json:"version"`
}

// Challenge is a HTTP handler that takes a POST request with LoginRequest in
// the body and verifies the signature of the provided challenge. If the
// signature is valid it logs in the user with the public key.
func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
		w.Header().Set("Access-Control-Allow-Headers", "content-type")
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Body == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var req LoginRequest
	err := decoder.Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	err = login.Verify(req.ChallengeHidden, req.ChallengeVisual, req.PublicKey, req.Signature, req.Version)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
