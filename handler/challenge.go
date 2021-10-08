// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"phobia.cloud/api/login"
)

// ChallengeResponse is a pair of ChallengeHidden and ChallengeVisual for
// Trezor login.
type ChallengeResponse struct {
	ChallengeHidden string `json:"challengeHidden"`
	ChallengeVisual string `json:"challengeVisual"`
}

// Challenge is a HTTP handler that takes a GET request without parameters and
// returns a ChallengeResponse for Trezor login.
func Challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	err := json.NewEncoder(w).Encode(ChallengeResponse{
		ChallengeHidden: login.ChallengeHidden(),
		ChallengeVisual: login.ChallengeVisual(),
	})
	if err != nil {
		log.Printf("error writing response to client: %v", err)
	}
}
