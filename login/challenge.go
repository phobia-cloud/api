// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package login

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// ChallengeHidden generates a new challenge hidden for the Trezor login.
//
// The challenge hidden is a hex-encoded string of 32 random bytes.
func ChallengeHidden() string {
	challengeBytes := make([]byte, 32)
	_, err := rand.Read(challengeBytes)
	if err != nil {
		// error in the random generator should never happen and is a good
		// reason to panic.
		panic(err)
	}
	return hex.EncodeToString(challengeBytes)
}

// ChallengeVisual generates a new challenge hidden for the Trezor login.
//
// The challenge visual is the current time in "YYYY-MM-DD HH:mm:ss" format.
func ChallengeVisual() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
