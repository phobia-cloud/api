// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package main

import (
	"encoding/json"
	"log"
	"net/http"

	"phobia.cloud/api/login"
)

type LoginChallenge struct {
	ChallengeHidden string `json:"challengeHidden"`
	ChallengeVisual string `json:"challengeVisual"`
}

func challengeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	err := json.NewEncoder(w).Encode(LoginChallenge{
		ChallengeHidden: login.ChallengeHidden(),
		ChallengeVisual: login.ChallengeVisual(),
	})
	if err != nil {
		log.Printf("error writing response to client: %v", err)
	}
}

type loginInfo struct {
	ChallengeHidden string `json:"challengeHidden"`
	ChallengeVisual string `json:"challengeVisual"`
	PublicKey       string `json:"publicKey"`
	Signature       string `json:"signature"`
	Version         int    `json:"version"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "post")
		w.Header().Set("Access-Control-Allow-Headers", "content-type")
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var info loginInfo
	err := decoder.Decode(&info)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	err = login.Verify(info.ChallengeHidden, info.ChallengeVisual, info.PublicKey, info.Signature, info.Version)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func main() {
	http.HandleFunc("/challenge", challengeHandler)
	http.HandleFunc("/login", loginHandler)

	log.Fatal(http.ListenAndServe(":5050", nil))
}
